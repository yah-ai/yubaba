//! Drift detection between declared `.yah/cloud/` config and live cloud state.
//!
//! Phase 1 scope (R040-T5): server existence + machine type + bucket existence.
//! Hostkey-fingerprint verification stays stubbed for now; the yubaba-side
//! `/health` probe is wired via the [`AgentProbe`] trait — callers that want
//! an agent-reachability check pass an implementation, otherwise no agent
//! findings are emitted.
//!
//! @yah:ticket(R470-T1, "Status journal + replay (.yah/cloud/status.jsonl)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-06T21:02:37Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R470)
//! @yah:next("Generalize the drift-only shape in crates/yah/cloud/src/status.rs to an append-only JSONL journal at .yah/cloud/status.jsonl. One record per reconciler decision: {at, asset, from, to, bytes?, blake3?}. Replay-on-load yields last_state_per_asset.")
//! @yah:next("Wire the reconciler's StaticAssetSyncReport emissions through this journal so every apply produces transition records.")
//! @yah:next("Implement tail-F-style subscribe for the --watch path: a Stream<Item = StatusEvent> that emits each new record as it's appended.")
//! @yah:verify("cargo test -p yah-cloud status")
//! @yah:verify("echo > .yah/cloud/status.jsonl && yah cloud apply --env cloud --service yah-desktop && test -s .yah/cloud/status.jsonl")
//! @arch:see(.yah/docs/working/W193-asset-dependency-status-surface.md)
//! @yah:handoff("Delivered: new crates/yah/cloud/src/asset_journal.rs with AssetState (8-state enum, kebab-case serde), AssetStatusEvent, and AssetStatusJournal (append/replay/subscribe). Path helper asset_status_journal() added to paths.rs → .yah/cloud/status.jsonl. Journal registered in lib.rs with pub re-exports. Wired into StaticAssetReconciler.up() → sync_to_r2/sync_to_minio → sync_assets: emits DriftBucket on hash_mismatch, Published (with correct from-state: PlaceholderOutput/PlaceholderFetch/PinnedNotPublished) on successful upload. In-process broadcast::Sender for subscribe(). 9 new asset_journal tests pass; 36 static_asset tests pass; cloud crate checks clean. Pre-existing cloud_init::tests::render_warden_channel... failure unchanged.")
//! @yah:verify("cargo test -p cloud asset_journal  # 9 pass")
//! @yah:verify("cargo test -p cloud --lib reconciler::static_asset  # 36 pass")
//! @yah:verify("cargo check -p cloud  # clean")

use async_trait::async_trait;

use crate::config::MachineConfig;
use crate::provider::{Location, MachineProvider, ServerStatus, ServerSummary};

/// Hook for probing a per-machine `yah-yubaba`. Implemented in the CLI on top
/// of `cloud-client` so this crate can stay independent of `reqwest` /
/// transport concerns.
#[async_trait]
pub trait AgentProbe: Send + Sync {
    /// `Ok(())` if the yubaba answered healthy. `Err(reason)` becomes the
    /// `AgentUnreachable.reason` string in the report.
    async fn probe(&self, machine: &MachineConfig) -> std::result::Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftFinding {
    /// No Hetzner server with the declared name.
    MissingServer,
    /// Server exists but its `server_type` doesn't match declared.
    WrongMachineType { declared: String, actual: String },
    /// Server exists but isn't Running.
    NotRunning(ServerStatus),
    /// Declared bucket isn't present at the location's S3 endpoint.
    MissingBucket { name: String },
    /// Live agent's hostkey fingerprint doesn't match declared (A8).
    HostkeyFingerprintMismatch { declared: String, actual: String },

    // ── Soft findings: surfaced but don't trigger non-zero exit ─────────────
    /// Couldn't probe the bucket (no S3 creds, transient API error).
    BucketUnchecked { name: String, reason: String },
    /// yah-yubaba didn't respond. Always emitted pre-A8 with a "lands with A8" reason.
    AgentUnreachable { reason: String },
    /// Hetzner API call failed for this machine; report is incomplete.
    ProviderError(String),
}

impl DriftFinding {
    /// Real divergence between declared and actual cloud state. Soft
    /// findings (uncheckable conditions, missing creds) return false.
    pub fn is_drift(&self) -> bool {
        matches!(
            self,
            Self::MissingServer
                | Self::WrongMachineType { .. }
                | Self::NotRunning(_)
                | Self::MissingBucket { .. }
                | Self::HostkeyFingerprintMismatch { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub struct MachineReport {
    pub name: String,
    pub server: Option<ServerSummary>,
    pub bucket_present: Option<bool>,
    pub findings: Vec<DriftFinding>,
}

impl MachineReport {
    pub fn has_drift(&self) -> bool {
        self.findings.iter().any(DriftFinding::is_drift)
    }

    /// One-word summary for the top of a status block.
    pub fn headline(&self) -> &'static str {
        if self
            .findings
            .iter()
            .any(|f| matches!(f, DriftFinding::MissingServer))
        {
            "not provisioned"
        } else if self.has_drift() {
            "drift"
        } else if self.server.is_some() {
            "in sync"
        } else {
            "unknown"
        }
    }
}

/// Run drift checks for a single declared machine.
///
/// - `provider = None` → cloud credentials aren't available; the report
///   contains a single `ProviderError` finding describing why.
/// - `agent = None`    → no yubaba probe attempted; no `AgentUnreachable`
///   finding is emitted regardless of server state. Pass an `AgentProbe`
///   when the caller wants reachability surfaced as drift.
pub async fn collect_machine_report(
    machine: &MachineConfig,
    provider: Option<&dyn MachineProvider>,
    agent: Option<&dyn AgentProbe>,
) -> MachineReport {
    let mut findings: Vec<DriftFinding> = Vec::new();
    let mut server: Option<ServerSummary> = None;
    let mut bucket_present: Option<bool> = None;

    let location = match Location::try_from(machine.location()) {
        Ok(l) => Some(l),
        Err(e) => {
            findings.push(DriftFinding::ProviderError(format!(
                "unknown location '{}': {e}",
                machine.location()
            )));
            None
        }
    };

    let Some(p) = provider else {
        findings.push(DriftFinding::ProviderError(
            "HETZNER_API_TOKEN not set — run `yah cloud secrets` for the contract".into(),
        ));
        return MachineReport {
            name: machine.name.clone(),
            server,
            bucket_present,
            findings,
        };
    };

    match p.find_server_by_name(&machine.name).await {
        Ok(Some(s)) => {
            if s.server_type != machine.server_type() {
                findings.push(DriftFinding::WrongMachineType {
                    declared: machine.server_type().to_string(),
                    actual: s.server_type.clone(),
                });
            }
            if !s.status.is_running() {
                findings.push(DriftFinding::NotRunning(s.status.clone()));
            }
            server = Some(s);
        }
        Ok(None) => findings.push(DriftFinding::MissingServer),
        Err(e) => findings.push(DriftFinding::ProviderError(format!(
            "find_server_by_name: {e}"
        ))),
    }

    if let (Some(spec), Some(loc)) = (&machine.bucket, &location) {
        match p.bucket_exists(&spec.name, loc.clone()).await {
            Ok(true) => bucket_present = Some(true),
            Ok(false) => {
                bucket_present = Some(false);
                findings.push(DriftFinding::MissingBucket {
                    name: spec.name.clone(),
                });
            }
            Err(e) => findings.push(DriftFinding::BucketUnchecked {
                name: spec.name.clone(),
                reason: e.to_string(),
            }),
        }
    }

    // Probe the yubaba iff the caller wired an `AgentProbe` AND there's a
    // server worth talking to. Pre-provision the agent gap is implied by
    // `MissingServer` and a second line would just be noise.
    if let (Some(_), Some(probe)) = (server.as_ref(), agent) {
        if let Err(reason) = probe.probe(machine).await {
            findings.push(DriftFinding::AgentUnreachable { reason });
        }
    }

    MachineReport {
        name: machine.name.clone(),
        server,
        bucket_present,
        findings,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BucketSpec;
    use crate::provider::{BucketAcl, BucketRef, ProjectId, ServerId, ServerSpec};
    use anyhow::{bail, Result};
    use async_trait::async_trait;
    use std::sync::Mutex;

    fn sample_machine() -> MachineConfig {
        MachineConfig {
            name: "noisetable-pdx-1".into(),
            provider: "hetzner".into(),
            location: Some("pdx".into()),
            server_type: Some("cpx22".into()),
            hosts_mirrors: vec!["noisetable".into()],
            mesh_tags: vec!["region:pdx".into()],
            region: None,
            zone: None,
            bucket: Some(BucketSpec {
                name: "noisetable-assets-pdx-1".into(),
                public_read: false,
            }),
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
        }
    }

    /// In-memory fake provider for drift-logic tests. Configurable
    /// per-name server presence and per-bucket existence.
    #[derive(Default)]
    struct FakeProvider {
        servers: Mutex<Vec<(String, ServerSummary)>>,
        buckets: Mutex<Vec<String>>,               // present bucket names
        bucket_check_fails: Mutex<Option<String>>, // if Some(reason), bucket_exists errors
    }

    impl FakeProvider {
        fn with_server(self, name: &str, summary: ServerSummary) -> Self {
            self.servers.lock().unwrap().push((name.into(), summary));
            self
        }
        fn with_bucket(self, name: &str) -> Self {
            self.buckets.lock().unwrap().push(name.into());
            self
        }
        fn fail_bucket_check(self, reason: &str) -> Self {
            *self.bucket_check_fails.lock().unwrap() = Some(reason.into());
            self
        }
    }

    #[async_trait]
    impl MachineProvider for FakeProvider {
        async fn ensure_project(&self, name: &str) -> Result<ProjectId> {
            Ok(ProjectId(name.into()))
        }
        async fn create_server(&self, _: &ProjectId, _: &ServerSpec, _: &str) -> Result<ServerId> {
            bail!("not used in drift tests")
        }
        async fn create_bucket(&self, _: &str, _: Location) -> Result<BucketRef> {
            bail!("not used in drift tests")
        }
        async fn server_status(&self, _: &ServerId) -> Result<ServerStatus> {
            bail!("not used in drift tests")
        }
        async fn find_server_by_name(&self, name: &str) -> Result<Option<ServerSummary>> {
            Ok(self
                .servers
                .lock()
                .unwrap()
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, s)| s.clone()))
        }
        async fn bucket_exists(&self, name: &str, _: Location) -> Result<bool> {
            if let Some(reason) = self.bucket_check_fails.lock().unwrap().as_deref() {
                bail!("{reason}");
            }
            Ok(self.buckets.lock().unwrap().iter().any(|b| b == name))
        }
        async fn destroy_server(&self, _: &ServerId) -> Result<()> {
            bail!("not used in drift tests")
        }
        async fn delete_bucket(&self, _: &str, _: Location) -> Result<()> {
            bail!("not used in drift tests")
        }
        async fn set_bucket_acl(&self, _: &str, _: Location, _: BucketAcl) -> Result<()> {
            bail!("not used in drift tests")
        }
    }

    /// In-memory `AgentProbe` for tests: configurable success/failure.
    struct FakeProbe {
        result: std::result::Result<(), String>,
    }

    #[async_trait]
    impl AgentProbe for FakeProbe {
        async fn probe(&self, _: &MachineConfig) -> std::result::Result<(), String> {
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn no_provider_reports_provider_error() {
        let report = collect_machine_report(&sample_machine(), None, None).await;
        assert_eq!(report.headline(), "unknown");
        assert!(matches!(
            report.findings.as_slice(),
            [DriftFinding::ProviderError(_)]
        ));
        // Soft finding — doesn't count as drift.
        assert!(!report.has_drift());
    }

    #[tokio::test]
    async fn missing_server_is_drift() {
        let provider = FakeProvider::default();
        let report = collect_machine_report(&sample_machine(), Some(&provider), None).await;
        assert_eq!(report.headline(), "not provisioned");
        assert!(report.has_drift());
        assert!(report.findings.contains(&DriftFinding::MissingServer));
    }

    #[tokio::test]
    async fn server_present_with_correct_type_and_bucket_is_in_sync() {
        let provider = FakeProvider::default()
            .with_server(
                "noisetable-pdx-1",
                ServerSummary {
                    id: ServerId("12345".into()),
                    server_type: "cpx22".into(),
                    status: ServerStatus::Running,
                    public_ipv4: None,
                    location: "hil".into(),
                },
            )
            .with_bucket("noisetable-assets-pdx-1");

        let report = collect_machine_report(&sample_machine(), Some(&provider), None).await;
        assert_eq!(report.headline(), "in sync");
        assert!(!report.has_drift());
        assert_eq!(report.bucket_present, Some(true));
        // No probe configured → no AgentUnreachable noise.
        assert!(!report
            .findings
            .iter()
            .any(|f| matches!(f, DriftFinding::AgentUnreachable { .. })));
    }

    #[tokio::test]
    async fn agent_probe_success_emits_no_finding() {
        let provider = FakeProvider::default()
            .with_server(
                "noisetable-pdx-1",
                ServerSummary {
                    id: ServerId("1".into()),
                    server_type: "cpx22".into(),
                    status: ServerStatus::Running,
                    public_ipv4: None,
                    location: "hil".into(),
                },
            )
            .with_bucket("noisetable-assets-pdx-1");
        let probe = FakeProbe { result: Ok(()) };
        let report = collect_machine_report(&sample_machine(), Some(&provider), Some(&probe)).await;
        assert!(!report
            .findings
            .iter()
            .any(|f| matches!(f, DriftFinding::AgentUnreachable { .. })));
    }

    #[tokio::test]
    async fn agent_probe_failure_emits_unreachable() {
        let provider = FakeProvider::default()
            .with_server(
                "noisetable-pdx-1",
                ServerSummary {
                    id: ServerId("1".into()),
                    server_type: "cpx22".into(),
                    status: ServerStatus::Running,
                    public_ipv4: None,
                    location: "hil".into(),
                },
            )
            .with_bucket("noisetable-assets-pdx-1");
        let probe = FakeProbe {
            result: Err("connection refused".into()),
        };
        let report = collect_machine_report(&sample_machine(), Some(&provider), Some(&probe)).await;
        let unreachable = report
            .findings
            .iter()
            .find(|f| matches!(f, DriftFinding::AgentUnreachable { .. }));
        assert!(unreachable.is_some());
        if let Some(DriftFinding::AgentUnreachable { reason }) = unreachable {
            assert!(reason.contains("connection refused"));
        }
        // AgentUnreachable is a soft finding — doesn't promote to drift.
        assert!(!report.has_drift());
    }

    #[tokio::test]
    async fn agent_probe_skipped_when_server_missing() {
        // Pre-provision: no server → don't bother probing the agent. The
        // missing-server finding already tells the operator the next step.
        let provider = FakeProvider::default();
        let probe = FakeProbe {
            result: Err("would fail if called".into()),
        };
        let report = collect_machine_report(&sample_machine(), Some(&provider), Some(&probe)).await;
        assert!(!report
            .findings
            .iter()
            .any(|f| matches!(f, DriftFinding::AgentUnreachable { .. })));
    }

    #[tokio::test]
    async fn wrong_machine_type_is_drift() {
        let provider = FakeProvider::default()
            .with_server(
                "noisetable-pdx-1",
                ServerSummary {
                    id: ServerId("12345".into()),
                    server_type: "cx22".into(), // declared cpx22
                    status: ServerStatus::Running,
                    public_ipv4: None,
                    location: "hil".into(),
                },
            )
            .with_bucket("noisetable-assets-pdx-1");

        let report = collect_machine_report(&sample_machine(), Some(&provider), None).await;
        assert!(report.has_drift());
        assert!(report.findings.iter().any(|f| matches!(
            f,
            DriftFinding::WrongMachineType { declared, actual }
                if declared == "cpx22" && actual == "cx22"
        )));
    }

    #[tokio::test]
    async fn missing_bucket_is_drift() {
        let provider = FakeProvider::default().with_server(
            "noisetable-pdx-1",
            ServerSummary {
                id: ServerId("1".into()),
                server_type: "cpx22".into(),
                status: ServerStatus::Running,
                public_ipv4: None,
                location: "hil".into(),
            },
        );

        let report = collect_machine_report(&sample_machine(), Some(&provider), None).await;
        assert!(report.has_drift());
        assert_eq!(report.bucket_present, Some(false));
        assert!(report.findings.iter().any(|f| matches!(
            f,
            DriftFinding::MissingBucket { name } if name == "noisetable-assets-pdx-1"
        )));
    }

    #[tokio::test]
    async fn bucket_check_failure_is_soft_finding() {
        let provider = FakeProvider::default()
            .with_server(
                "noisetable-pdx-1",
                ServerSummary {
                    id: ServerId("1".into()),
                    server_type: "cpx22".into(),
                    status: ServerStatus::Running,
                    public_ipv4: None,
                    location: "hil".into(),
                },
            )
            .fail_bucket_check("S3 credentials not configured");

        let report = collect_machine_report(&sample_machine(), Some(&provider), None).await;
        // Real drift only — soft finding doesn't trip.
        assert!(!report.has_drift());
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f, DriftFinding::BucketUnchecked { .. })));
    }

    #[tokio::test]
    async fn server_off_is_drift() {
        let provider = FakeProvider::default()
            .with_server(
                "noisetable-pdx-1",
                ServerSummary {
                    id: ServerId("1".into()),
                    server_type: "cpx22".into(),
                    status: ServerStatus::Off,
                    public_ipv4: None,
                    location: "hil".into(),
                },
            )
            .with_bucket("noisetable-assets-pdx-1");

        let report = collect_machine_report(&sample_machine(), Some(&provider), None).await;
        assert!(report.has_drift());
        assert!(report
            .findings
            .iter()
            .any(|f| matches!(f, DriftFinding::NotRunning(ServerStatus::Off))));
    }
}
