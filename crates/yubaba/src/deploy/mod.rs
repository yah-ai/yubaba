//! @yah:relay(R278, "Cross-cutter — Rollout API + gate evaluator (yubaba /v1/rollouts)")
//! @yah:assignee(bundle-anthropic-miravel)
//! @yah:at(2026-06-01T02:26:21Z)
//! @yah:status(in-progress)
//! @yah:parent(Q273)
//! @yah:next("F1: POST /v1/rollouts with linear strategy + staging→prod (v1 slice per yah-yubaba-ci-cd.md)")
//! @yah:next("F2: Prometheus gate evaluator — http_5xx_rate + p95_latency_ms gates")
//! @yah:next("F3: raft mirror metadata for rollout state (depends on Tier-4 raft being live; degenerate-raft fine for v1)")
//! @yah:next("F4: rollout policy schema in yah-workload-spec")
//! @yah:gotcha("Start condition: Tier-3 F2 green (one workload that can actually be rolled). Filed now so the design intent stays visible.")
//! @yah:gotcha("Spec-only today — no /v1/rollouts, no gate evaluator, no rollout policy schema")
//! @arch:see(.yah/docs/working/W140-yah-yubaba-ci-cd.md)
//! @arch:see(.yah/docs/architecture/A054-yah-workload-spec.md)
//!
//! @yah:ticket(R278-F2, "Prometheus gate evaluator — http_5xx_rate + p95_latency_ms")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T02:31:23Z)
//! @yah:status(review)
//! @yah:parent(R278)
//! @yah:next("Add src/rollout/gate.rs with PrometheusGateEvaluator (reqwest to Prometheus API)")
//! @yah:next("Parse condition strings (< 0.01, < 200) and evaluate against Prometheus query_range results")
//! @yah:next("Support window parsing (5m, 10m) for gate.window field")
//! @arch:see(.yah/docs/working/W140-yah-yubaba-ci-cd.md)
//! @yah:handoff("PrometheusGateEvaluator in yubaba/src/rollout/gate.rs. Queries /api/v1/query (instant). Metric name → PromQL template mapping for http_5xx_rate + p95_latency_ms; custom metrics pass through verbatim. Condition parsing: < <= > >=. 9 unit tests all green.")

pub mod env_validate;
pub mod mesh_resolve;
pub mod secret_mount;
