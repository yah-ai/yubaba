//! `observability.*` verb signatures — monitoring and alerting catalog (R409-T12).
//!
//! Five verbs covering the alerting and incident-management plane.
//! Exemplar tier-A providers: PagerDuty, Grafana Cloud, Datadog.
//!
//! - `observability.alert.list`         — enumerate active/all alerts
//! - `observability.alert.ack`          — acknowledge an alert
//! - `observability.incident.open`      — open a new incident
//! - `observability.incident.close`     — resolve/close an incident
//! - `observability.dashboard.snapshot` — capture a dashboard snapshot URL
//!
//! The verb shapes are deliberately narrow — adapters map provider-specific
//! state to the closed enums here. Free-form detail rides in optional `detail`
//! fields rather than proliferating variants.

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── observability.alert.list ──────────────────────────────────────────────

/// Marker type for `observability.alert.list`.
pub struct ObservabilityAlertList;

/// Request body for `observability.alert.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityAlertListInput {
    /// Severity filter: `"critical"`, `"warning"`, `"info"`. `None` returns
    /// alerts of all severities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// When `true` (default), only return currently firing alerts. Set to
    /// `false` to include resolved and silenced alerts.
    #[serde(default = "bool_true")]
    pub active_only: bool,
}

fn bool_true() -> bool {
    true
}

/// One alert entry in the list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct AlertEntry {
    /// Provider-issued alert or rule ID.
    pub id: String,
    /// Human-readable alert title.
    pub title: String,
    /// Severity bucket: `"critical"`, `"warning"`, `"info"`, `"unknown"`.
    pub severity: String,
    /// Lifecycle state: `"firing"`, `"resolved"`, `"silenced"`, `"unknown"`.
    pub state: String,
    /// RFC 3339 timestamp of when this alert began firing. `None` when
    /// the provider does not report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Provider-specific detail string — reason text, runbook link, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Response body for `observability.alert.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityAlertListOutput {
    pub alerts: Vec<AlertEntry>,
}

impl InternalVerb for ObservabilityAlertList {
    type Input = ObservabilityAlertListInput;
    type Output = ObservabilityAlertListOutput;
    const ID: &'static str = "observability.alert.list";
    const CATEGORY: VerbCategory = VerbCategory::Observability;
}

// ── observability.alert.ack ───────────────────────────────────────────────

/// Marker type for `observability.alert.ack`.
pub struct ObservabilityAlertAck;

/// Request body for `observability.alert.ack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityAlertAckInput {
    /// Provider-issued alert ID.
    pub id: String,
    /// Acknowledgement message or reason. Encouraged but optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Response body for `observability.alert.ack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityAlertAckOutput {
    /// `true` if the alert transitioned to acknowledged; `false` when it was
    /// already acknowledged before this call (idempotent).
    pub acknowledged: bool,
}

impl InternalVerb for ObservabilityAlertAck {
    type Input = ObservabilityAlertAckInput;
    type Output = ObservabilityAlertAckOutput;
    const ID: &'static str = "observability.alert.ack";
    const CATEGORY: VerbCategory = VerbCategory::Observability;
}

// ── observability.incident.open ───────────────────────────────────────────

/// Marker type for `observability.incident.open`.
pub struct ObservabilityIncidentOpen;

/// Request body for `observability.incident.open`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityIncidentOpenInput {
    pub title: String,
    /// Severity: `"critical"`, `"major"`, `"minor"`, `"info"`. Adapters
    /// map to provider-specific levels (e.g. PagerDuty P1–P5).
    pub severity: String,
    /// Optional incident body — description, timeline, runbook link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Response body for `observability.incident.open`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityIncidentOpenOutput {
    /// Provider-issued incident ID.
    pub id: String,
    /// URL to the incident page in the provider's UI. `None` when the
    /// provider doesn't return one at creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl InternalVerb for ObservabilityIncidentOpen {
    type Input = ObservabilityIncidentOpenInput;
    type Output = ObservabilityIncidentOpenOutput;
    const ID: &'static str = "observability.incident.open";
    const CATEGORY: VerbCategory = VerbCategory::Observability;
}

// ── observability.incident.close ──────────────────────────────────────────

/// Marker type for `observability.incident.close`.
pub struct ObservabilityIncidentClose;

/// Request body for `observability.incident.close`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityIncidentCloseInput {
    /// Provider-issued incident ID from a prior `observability.incident.open`.
    pub id: String,
    /// Resolution summary. Encouraged but optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
}

/// Response body for `observability.incident.close`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityIncidentCloseOutput {
    /// `true` if the incident was open and is now closed; `false` if it was
    /// already resolved (idempotent).
    pub closed: bool,
}

impl InternalVerb for ObservabilityIncidentClose {
    type Input = ObservabilityIncidentCloseInput;
    type Output = ObservabilityIncidentCloseOutput;
    const ID: &'static str = "observability.incident.close";
    const CATEGORY: VerbCategory = VerbCategory::Observability;
}

// ── observability.dashboard.snapshot ─────────────────────────────────────

/// Marker type for `observability.dashboard.snapshot`.
pub struct ObservabilityDashboardSnapshot;

/// Request body for `observability.dashboard.snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityDashboardSnapshotInput {
    /// Provider-specific dashboard identifier (UID, ID, or slug).
    pub dashboard_id: String,
    /// Time range for the snapshot. Provider-specific formats are accepted
    /// (e.g. `"last_1h"`, `"last_24h"`, `"2026-06-01T00:00Z/2026-06-02T00:00Z"`).
    /// `None` uses the provider's default view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_range: Option<String>,
}

/// Response body for `observability.dashboard.snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct ObservabilityDashboardSnapshotOutput {
    /// Publicly-accessible (or token-authenticated) URL to the snapshot.
    pub url: String,
    /// RFC 3339 expiry timestamp. `None` when the provider does not expire
    /// snapshots automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl InternalVerb for ObservabilityDashboardSnapshot {
    type Input = ObservabilityDashboardSnapshotInput;
    type Output = ObservabilityDashboardSnapshotOutput;
    const ID: &'static str = "observability.dashboard.snapshot";
    const CATEGORY: VerbCategory = VerbCategory::Observability;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        let ids = [
            ObservabilityAlertList::ID,
            ObservabilityAlertAck::ID,
            ObservabilityIncidentOpen::ID,
            ObservabilityIncidentClose::ID,
            ObservabilityDashboardSnapshot::ID,
        ];
        for id in ids {
            assert!(id.starts_with("observability."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_observability_category() {
        assert_eq!(
            ObservabilityAlertList::CATEGORY,
            VerbCategory::Observability
        );
        assert_eq!(ObservabilityAlertAck::CATEGORY, VerbCategory::Observability);
        assert_eq!(
            ObservabilityIncidentOpen::CATEGORY,
            VerbCategory::Observability
        );
        assert_eq!(
            ObservabilityIncidentClose::CATEGORY,
            VerbCategory::Observability
        );
        assert_eq!(
            ObservabilityDashboardSnapshot::CATEGORY,
            VerbCategory::Observability
        );
    }

    #[test]
    fn alert_list_input_defaults_active_only_true() {
        let wire = r#"{"severity":"critical"}"#;
        let parsed: ObservabilityAlertListInput = serde_json::from_str(wire).unwrap();
        assert!(parsed.active_only, "active_only should default to true");
        assert_eq!(parsed.severity.as_deref(), Some("critical"));
    }

    #[test]
    fn alert_list_input_no_severity_returns_all() {
        let wire = r#"{}"#;
        let parsed: ObservabilityAlertListInput = serde_json::from_str(wire).unwrap();
        assert!(parsed.severity.is_none());
        assert!(parsed.active_only);
    }

    #[test]
    fn alert_entry_round_trips() {
        let entry = AlertEntry {
            id: "a1".into(),
            title: "CPU high".into(),
            severity: "critical".into(),
            state: "firing".into(),
            started_at: Some("2026-06-06T00:00:00Z".into()),
            detail: None,
        };
        let wire = serde_json::to_string(&entry).unwrap();
        let back: AlertEntry = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.severity, "critical");
        assert!(back.detail.is_none());
    }

    #[test]
    fn incident_open_output_omits_url_when_absent() {
        let out = ObservabilityIncidentOpenOutput {
            id: "INC-1".into(),
            url: None,
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("url"));
    }

    #[test]
    fn dashboard_snapshot_time_range_optional() {
        let no_range = r#"{"dashboard_id":"abc123"}"#;
        let parsed: ObservabilityDashboardSnapshotInput = serde_json::from_str(no_range).unwrap();
        assert!(parsed.time_range.is_none());

        let with_range = r#"{"dashboard_id":"abc123","time_range":"last_24h"}"#;
        let parsed: ObservabilityDashboardSnapshotInput = serde_json::from_str(with_range).unwrap();
        assert_eq!(parsed.time_range.as_deref(), Some("last_24h"));
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let alert_list = VerbDescriptor::for_verb::<ObservabilityAlertList>();
        assert_eq!(alert_list.id, "observability.alert.list");
        assert!(alert_list.output_schema.to_string().contains("alerts"));

        let snapshot = VerbDescriptor::for_verb::<ObservabilityDashboardSnapshot>();
        assert_eq!(snapshot.id, "observability.dashboard.snapshot");
        assert!(snapshot.output_schema.to_string().contains("url"));
    }
}
