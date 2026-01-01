//! `ci.*` verb signatures — external CI pipeline catalog (R409-T12).
//!
//! Three verbs for talking to external CI systems. Note: **qed** (W126) is
//! yah's own scheduler; these verbs are for when yah does not own the CI
//! substrate and needs to talk to GitHub Actions, GitLab CI, CircleCI, etc.
//!
//! - `ci.pipeline.run`    — trigger a pipeline run
//! - `ci.pipeline.status` — query a run's lifecycle phase
//! - `ci.artifact.fetch`  — get a download URL for a build artifact
//!
//! Adapters are responsible for mapping `pipeline` (a provider-specific
//! identifier — repo path, workflow filename, numeric ID) and `git_ref`
//! (branch, tag, or SHA) to the provider's API shape.

use serde::{Deserialize, Serialize};

use super::{InternalVerb, VerbCategory};

// ── ci.pipeline.run ───────────────────────────────────────────────────────

/// Marker type for `ci.pipeline.run`.
pub struct CiPipelineRun;

/// Request body for `ci.pipeline.run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CiPipelineRunInput {
    /// Provider-specific pipeline identifier: a workflow filename on GitHub
    /// Actions (`"release.yml"`), a numeric pipeline ID on GitLab, a pipeline
    /// slug on CircleCI, etc.
    pub pipeline: String,
    /// Git ref to run the pipeline against: branch name, tag, or full SHA.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// Key-value variables to pass to the pipeline run. Provider-specific
    /// interpretation; `None` uses the pipeline's own defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<std::collections::BTreeMap<String, String>>,
}

/// Response body for `ci.pipeline.run`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CiPipelineRunOutput {
    /// Provider-issued run identifier. Opaque; used in `ci.pipeline.status`
    /// and `ci.artifact.fetch`.
    pub run_id: String,
    /// URL to the run in the provider's UI. `None` when not available at
    /// trigger time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl InternalVerb for CiPipelineRun {
    type Input = CiPipelineRunInput;
    type Output = CiPipelineRunOutput;
    const ID: &'static str = "ci.pipeline.run";
    const CATEGORY: VerbCategory = VerbCategory::Ci;
}

// ── ci.pipeline.status ────────────────────────────────────────────────────

/// Marker type for `ci.pipeline.status`.
pub struct CiPipelineStatus;

/// Request body for `ci.pipeline.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CiPipelineStatusInput {
    /// Run ID from a prior `ci.pipeline.run`.
    pub run_id: String,
}

/// Canonical pipeline lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PipelinePhase {
    /// Queued but not yet started.
    Pending,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Passing,
    /// Completed with failures.
    Failing,
    /// Cancelled before completion.
    Cancelled,
    /// Phase couldn't be determined or maps to no known phase.
    Unknown,
}

/// Response body for `ci.pipeline.status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CiPipelineStatusOutput {
    pub phase: PipelinePhase,
    /// URL to the run in the provider's UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Free-form detail — provider error message, failure summary. Populated
    /// when `phase` is `failing` or `unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl InternalVerb for CiPipelineStatus {
    type Input = CiPipelineStatusInput;
    type Output = CiPipelineStatusOutput;
    const ID: &'static str = "ci.pipeline.status";
    const CATEGORY: VerbCategory = VerbCategory::Ci;
}

// ── ci.artifact.fetch ─────────────────────────────────────────────────────

/// Marker type for `ci.artifact.fetch`.
pub struct CiArtifactFetch;

/// Request body for `ci.artifact.fetch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CiArtifactFetchInput {
    /// Run ID from a prior `ci.pipeline.run`.
    pub run_id: String,
    /// Provider-specific artifact name or path (e.g. `"dist/app.tar.gz"` on
    /// GitHub Actions, a numeric artifact ID on GitLab).
    pub artifact_name: String,
}

/// Response body for `ci.artifact.fetch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CiArtifactFetchOutput {
    /// Pre-signed or authenticated download URL. May be time-limited; see
    /// `expires_at`.
    pub download_url: String,
    /// RFC 3339 expiry of the download URL. `None` when the URL is permanent
    /// or the provider doesn't report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Artifact size in bytes. `None` when not reported by the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

impl InternalVerb for CiArtifactFetch {
    type Input = CiArtifactFetchInput;
    type Output = CiArtifactFetchOutput;
    const ID: &'static str = "ci.artifact.fetch";
    const CATEGORY: VerbCategory = VerbCategory::Ci;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_ids_match_canonical_namespace() {
        for id in [CiPipelineRun::ID, CiPipelineStatus::ID, CiArtifactFetch::ID] {
            assert!(id.starts_with("ci."), "{id}");
        }
    }

    #[test]
    fn verbs_are_under_ci_category() {
        assert_eq!(CiPipelineRun::CATEGORY, VerbCategory::Ci);
        assert_eq!(CiPipelineStatus::CATEGORY, VerbCategory::Ci);
        assert_eq!(CiArtifactFetch::CATEGORY, VerbCategory::Ci);
    }

    #[test]
    fn pipeline_run_input_ref_renamed_in_wire() {
        let wire = r#"{"pipeline":"release.yml","ref":"main"}"#;
        let parsed: CiPipelineRunInput = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.git_ref, "main");
        // Verify it serializes back as "ref".
        let back = serde_json::to_value(&parsed).unwrap();
        assert!(back.get("ref").is_some(), "must serialize as 'ref'");
        assert!(back.get("git_ref").is_none());
    }

    #[test]
    fn pipeline_run_variables_optional() {
        let no_vars = r#"{"pipeline":"build.yml","ref":"main"}"#;
        let parsed: CiPipelineRunInput = serde_json::from_str(no_vars).unwrap();
        assert!(parsed.variables.is_none());

        let with_vars =
            r#"{"pipeline":"build.yml","ref":"main","variables":{"ENV":"staging"}}"#;
        let parsed: CiPipelineRunInput = serde_json::from_str(with_vars).unwrap();
        assert_eq!(
            parsed.variables.as_ref().unwrap().get("ENV").map(|s| s.as_str()),
            Some("staging")
        );
    }

    #[test]
    fn pipeline_phase_is_snake_case() {
        assert_eq!(serde_json::to_string(&PipelinePhase::Passing).unwrap(), "\"passing\"");
        assert_eq!(serde_json::to_string(&PipelinePhase::Unknown).unwrap(), "\"unknown\"");
    }

    #[test]
    fn pipeline_status_omits_detail_when_absent() {
        let out = CiPipelineStatusOutput { phase: PipelinePhase::Running, url: None, detail: None };
        let wire = serde_json::to_value(&out).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("detail"));
    }

    #[test]
    fn artifact_fetch_output_omits_optional_fields_when_absent() {
        let out = CiArtifactFetchOutput {
            download_url: "https://example.com/artifact.tar.gz".into(),
            expires_at: None,
            size_bytes: None,
        };
        let wire = serde_json::to_value(&out).unwrap();
        assert!(!wire.as_object().unwrap().contains_key("expires_at"));
        assert!(!wire.as_object().unwrap().contains_key("size_bytes"));
    }

    #[cfg(feature = "json-schema")]
    #[test]
    fn verbs_emit_schemas_via_for_verb() {
        use super::super::VerbDescriptor;

        let run = VerbDescriptor::for_verb::<CiPipelineRun>();
        assert_eq!(run.id, "ci.pipeline.run");
        assert!(run.input_schema.to_string().contains("pipeline"));

        let status = VerbDescriptor::for_verb::<CiPipelineStatus>();
        assert_eq!(status.id, "ci.pipeline.status");
        assert!(status.output_schema.to_string().contains("phase"));

        let fetch = VerbDescriptor::for_verb::<CiArtifactFetch>();
        assert_eq!(fetch.id, "ci.artifact.fetch");
        assert!(fetch.output_schema.to_string().contains("download_url"));
    }
}
