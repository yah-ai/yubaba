//! Prometheus-backed SLO gate evaluator (F2).
//!
//! Translates metric names from the rollout policy into PromQL queries,
//! fetches the current instant value from a Prometheus-compatible endpoint
//! (VictoriaMetrics, Prometheus, Thanos), and applies the condition string.
//!
//! Metric name → PromQL template mapping:
//!
//! | Policy metric name   | PromQL template                                                         |
//! |----------------------|-------------------------------------------------------------------------|
//! | `http_5xx_rate`      | `sum(rate(http_requests_total{status=~"5.."}[{window}])) / sum(rate(http_requests_total[{window}]))` |
//! | `p95_latency_ms`     | `histogram_quantile(0.95, sum(rate(http_request_duration_milliseconds_bucket[{window}])) by (le))` |
//! | anything else        | used verbatim as a PromQL expression (allows custom metrics)            |

use anyhow::{bail, Context, Result};
use reqwest::Client;
use workload_spec::rollout::RolloutGate;

/// Built-in metric name → PromQL template pairs.
///
/// `{window}` is replaced with the gate's `window` field (e.g. `"5m"`).
static METRIC_TEMPLATES: &[(&str, &str)] = &[
    (
        "http_5xx_rate",
        concat!(
            "sum(rate(http_requests_total{status=~\"5..\"}[{window}]))",
            " / ",
            "sum(rate(http_requests_total[{window}]))",
        ),
    ),
    (
        "p95_latency_ms",
        concat!(
            "histogram_quantile(0.95, ",
            "sum(rate(http_request_duration_milliseconds_bucket[{window}])) by (le)",
            ")",
        ),
    ),
];

/// Evaluates rollout gates by querying a Prometheus-compatible `/api/v1/query`
/// endpoint.
#[derive(Clone)]
pub struct PrometheusGateEvaluator {
    client: Client,
    base_url: String,
}

impl PrometheusGateEvaluator {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into(),
        }
    }

    /// Evaluate one gate. Returns `true` when the condition holds (gate
    /// passes), `false` when it fails, and an error when the metric can't be
    /// fetched or parsed.
    pub async fn evaluate(&self, gate: &RolloutGate) -> Result<bool> {
        let query = build_promql(gate);
        let value = self.query_instant(&query).await?;
        evaluate_condition(&gate.condition, value)
    }

    /// Query `GET /api/v1/query` for the current instant value of `expr`.
    ///
    /// Returns `0.0` when the result set is empty (no traffic = no errors).
    async fn query_instant(&self, expr: &str) -> Result<f64> {
        let url = format!("{}/api/v1/query", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .get(&url)
            .query(&[("query", expr)])
            .send()
            .await
            .with_context(|| format!("querying Prometheus at {url}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Prometheus returned {status}: {body}");
        }

        let body: serde_json::Value = resp.json().await.context("parsing Prometheus response")?;
        extract_instant_scalar(&body)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build the PromQL expression for a gate, expanding `{window}`.
fn build_promql(gate: &RolloutGate) -> String {
    let template = METRIC_TEMPLATES
        .iter()
        .find(|(name, _)| *name == gate.metric)
        .map(|(_, tmpl)| *tmpl)
        .unwrap_or(gate.metric.as_str());
    template.replace("{window}", &gate.window)
}

/// Extract the first scalar value from a Prometheus instant-query response.
///
/// Instant result shape:
/// ```json
/// { "data": { "resultType": "vector",
///             "result": [{ "metric": {…}, "value": [timestamp, "0.003"] }] } }
/// ```
fn extract_instant_scalar(body: &serde_json::Value) -> Result<f64> {
    let result = body
        .pointer("/data/result")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!("unexpected Prometheus response shape: missing /data/result")
        })?;

    if result.is_empty() {
        return Ok(0.0);
    }

    let scalar_str = result[0]
        .pointer("/value/1")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing scalar string at /data/result[0]/value/1"))?;

    scalar_str
        .parse::<f64>()
        .with_context(|| format!("parsing Prometheus scalar '{scalar_str}'"))
}

/// Apply a condition string to a numeric value.
///
/// Supported operators: `<`, `<=`, `>`, `>=`.
fn evaluate_condition(condition: &str, value: f64) -> Result<bool> {
    let s = condition.trim();

    // Try each operator longest-first to avoid `<` consuming `<=`.
    if let Some(rhs) = s.strip_prefix("<= ").or_else(|| s.strip_prefix("<=")) {
        let t = parse_threshold(rhs, condition)?;
        return Ok(value <= t);
    }
    if let Some(rhs) = s.strip_prefix(">= ").or_else(|| s.strip_prefix(">=")) {
        let t = parse_threshold(rhs, condition)?;
        return Ok(value >= t);
    }
    if let Some(rhs) = s.strip_prefix("< ").or_else(|| s.strip_prefix('<')) {
        let t = parse_threshold(rhs, condition)?;
        return Ok(value < t);
    }
    if let Some(rhs) = s.strip_prefix("> ").or_else(|| s.strip_prefix('>')) {
        let t = parse_threshold(rhs, condition)?;
        return Ok(value > t);
    }

    bail!(
        "unrecognised gate condition '{condition}' — \
         expected one of: < <value> | <= <value> | > <value> | >= <value>"
    )
}

fn parse_threshold(s: &str, full_condition: &str) -> Result<f64> {
    s.trim()
        .parse::<f64>()
        .with_context(|| format!("parsing threshold in gate condition '{full_condition}'"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_lt() {
        assert!(evaluate_condition("< 0.01", 0.005).unwrap());
        assert!(!evaluate_condition("< 0.01", 0.02).unwrap());
        assert!(!evaluate_condition("< 0.01", 0.01).unwrap()); // strict
    }

    #[test]
    fn condition_lte() {
        assert!(evaluate_condition("<= 200", 200.0).unwrap());
        assert!(evaluate_condition("<= 200", 199.0).unwrap());
        assert!(!evaluate_condition("<= 200", 201.0).unwrap());
    }

    #[test]
    fn condition_gt() {
        assert!(evaluate_condition("> 0.99", 1.0).unwrap());
        assert!(!evaluate_condition("> 0.99", 0.99).unwrap()); // strict
    }

    #[test]
    fn condition_gte() {
        assert!(evaluate_condition(">= 0.99", 0.99).unwrap());
        assert!(!evaluate_condition(">= 0.99", 0.98).unwrap());
    }

    #[test]
    fn condition_unrecognised() {
        assert!(evaluate_condition("!= 0.01", 0.0).is_err());
    }

    #[test]
    fn extract_scalar_empty_returns_zero() {
        let body = serde_json::json!({ "data": { "result": [] } });
        assert_eq!(extract_instant_scalar(&body).unwrap(), 0.0);
    }

    #[test]
    fn extract_scalar_present() {
        let body = serde_json::json!({
            "data": {
                "result": [{ "metric": {}, "value": [1700000000u64, "0.003"] }]
            }
        });
        let v = extract_instant_scalar(&body).unwrap();
        assert!((v - 0.003).abs() < f64::EPSILON);
    }

    #[test]
    fn build_promql_known_metric() {
        let gate = RolloutGate {
            metric: "http_5xx_rate".into(),
            condition: "< 0.01".into(),
            window: "5m".into(),
        };
        let q = build_promql(&gate);
        assert!(q.contains("5m"), "window substituted");
        assert!(q.contains("http_requests_total"), "template used");
    }

    #[test]
    fn build_promql_custom_metric() {
        let gate = RolloutGate {
            metric: "my_custom_gauge".into(),
            condition: "< 100".into(),
            window: "1m".into(),
        };
        // Custom metric → used verbatim.
        assert_eq!(build_promql(&gate), "my_custom_gauge");
    }
}
