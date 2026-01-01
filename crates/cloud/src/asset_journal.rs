//! Append-only JSONL journal for static-asset reconciler decisions (R470-T1).
//!
//! Path: `.yah/cloud/status.jsonl`. One record per reconciler decision.
//! Replay yields `last_state_per_asset` — the source of truth for
//! `yah cloud status` without `--check`. In-process `subscribe()` lets
//! the desktop panel react to transitions without polling.
//!
//! Wire shape matches `.yah/events.jsonl`: append-only, concurrent writers
//! are safe (each `append` is one `write` syscall on the line), replayable
//! to a HashMap keyed by `"<service>:<filename>"`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// The 8 canonical asset states. All surfaces (CLI, panel, JSON, RPC)
/// use these exact kebab-case strings — lock this vocabulary before extending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetState {
    /// Catalog blake3 non-zero; HEAD against bucket matches; fetch.blake3 (if
    /// present) non-zero. No operator action needed.
    Published,
    /// `[[asset]].blake3` is the 64-zero sentinel. Run `yah cloud apply`.
    PlaceholderOutput,
    /// `[asset.derive.fetch].blake3` is the 64-zero sentinel. Run `yah cloud apply`.
    PlaceholderFetch,
    /// Catalog blake3 non-zero; HEAD misses (bucket key absent). Run `yah cloud apply`.
    PinnedNotPublished,
    /// HEAD exists but its recomputed hash ≠ catalog blake3. Investigate first.
    DriftBucket,
    /// Fetch URL produced a different blake3 than the pinned fetch.blake3.
    /// Regenerate transform output and open a new blake3 cycle.
    DriftUpstream,
    /// Recipe execution failed during last reconcile. Inspect logs; fix recipe.
    TransformBroken,
    /// Declared optional; current host/cfg predicate is false. No action needed.
    NotRequired,
}

/// One state transition appended to `.yah/cloud/status.jsonl`.
///
/// `asset` is `"<service>:<filename>"`, e.g.
/// `"yah-desktop:yah-desktop/whisper/distil-large-v3-q5_1.bin"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetStatusEvent {
    pub at: DateTime<Utc>,
    pub asset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<AssetState>,
    pub to: AssetState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
}

/// Append-only JSONL journal at `.yah/cloud/status.jsonl`.
///
/// **Write**: `append` serialises one event as a JSONL line. Non-fatal — a
/// write failure is logged and the reconciler continues.
///
/// **Read**: `last_state_per_asset` replays the journal, returning a
/// `HashMap<asset_key, AssetState>` keyed by `"<service>:<filename>"`.
/// Returns an empty map when the journal file doesn't exist yet.
///
/// **Watch**: `subscribe` returns a `broadcast::Receiver` for in-process
/// callers (desktop panel). Cross-process consumers (the `--watch` CLI flag)
/// tail the file and parse new JSONL lines directly.
pub struct AssetStatusJournal {
    path: PathBuf,
    tx: Arc<broadcast::Sender<AssetStatusEvent>>,
}

impl AssetStatusJournal {
    pub fn new(path: PathBuf) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self { path, tx: Arc::new(tx) }
    }

    /// Create a journal rooted at `<workspace_root>/.yah/cloud/status.jsonl`.
    pub fn at_workspace(workspace_root: &Path) -> Self {
        Self::new(crate::paths::asset_status_journal(workspace_root))
    }

    /// Append one event. Best-effort: failures are warned, not propagated.
    pub async fn append(&self, event: &AssetStatusEvent) {
        if let Err(e) = self.try_append(event).await {
            tracing::warn!(
                asset = %event.asset,
                error = %e,
                "asset status journal write failed (non-fatal)"
            );
        } else {
            // Ignore send errors — no active subscribers is fine.
            let _ = self.tx.send(event.clone());
        }
    }

    async fn try_append(&self, event: &AssetStatusEvent) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut line = serde_json::to_string(event).context("serializing AssetStatusEvent")?;
        line.push('\n');
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .with_context(|| format!("opening {}", self.path.display()))?;
        file.write_all(line.as_bytes())
            .await
            .with_context(|| format!("writing to {}", self.path.display()))?;
        Ok(())
    }

    /// Replay the journal file and return the most recent state per asset key.
    /// Returns an empty map when the journal doesn't exist (before first apply).
    pub async fn last_state_per_asset(&self) -> HashMap<String, AssetState> {
        match self.try_replay().await {
            Ok(map) => map,
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    journal = %self.path.display(),
                    "journal replay failed — returning empty map",
                );
                HashMap::new()
            }
        }
    }

    async fn try_replay(&self) -> Result<HashMap<String, AssetState>> {
        let content = match tokio::fs::read_to_string(&self.path).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };

        let mut map = HashMap::new();
        for (lineno, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<AssetStatusEvent>(line) {
                Ok(event) => {
                    map.insert(event.asset.clone(), event.to);
                }
                Err(e) => {
                    tracing::warn!(
                        line = lineno + 1,
                        journal = %self.path.display(),
                        error = %e,
                        "skipping unparseable journal line",
                    );
                }
            }
        }
        Ok(map)
    }

    /// Subscribe to in-process state-change events. Each call yields an
    /// independent receiver; up to 256 events are buffered before the
    /// oldest is dropped for a lagging receiver.
    ///
    /// For cross-process `--watch`, tail the journal file and parse JSONL lines.
    pub fn subscribe(&self) -> broadcast::Receiver<AssetStatusEvent> {
        self.tx.subscribe()
    }

    /// Path to the journal file on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_event(asset: &str, to: AssetState) -> AssetStatusEvent {
        AssetStatusEvent {
            at: Utc::now(),
            asset: asset.to_string(),
            from: None,
            to,
            bytes: None,
            blake3: None,
        }
    }

    #[test]
    fn asset_state_serde_round_trip() {
        let cases = [
            (AssetState::Published, "\"published\""),
            (AssetState::PlaceholderOutput, "\"placeholder-output\""),
            (AssetState::PlaceholderFetch, "\"placeholder-fetch\""),
            (AssetState::PinnedNotPublished, "\"pinned-not-published\""),
            (AssetState::DriftBucket, "\"drift-bucket\""),
            (AssetState::DriftUpstream, "\"drift-upstream\""),
            (AssetState::TransformBroken, "\"transform-broken\""),
            (AssetState::NotRequired, "\"not-required\""),
        ];
        for (state, expected_json) in cases {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(json, expected_json, "serialize {state:?}");
            let rt: AssetState = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, state, "round-trip {state:?}");
        }
    }

    #[test]
    fn event_serde_round_trip() {
        let event = AssetStatusEvent {
            at: DateTime::parse_from_rfc3339("2026-06-06T21:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            asset: "yah-desktop:whisper/model.bin".to_string(),
            from: Some(AssetState::PinnedNotPublished),
            to: AssetState::Published,
            bytes: Some(1024),
            blake3: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let rt: AssetStatusEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.asset, event.asset);
        assert_eq!(rt.from, event.from);
        assert_eq!(rt.to, event.to);
        assert_eq!(rt.bytes, event.bytes);
        assert_eq!(rt.blake3, event.blake3);
    }

    #[test]
    fn event_skips_none_fields_in_json() {
        let event = sample_event("svc:file.bin", AssetState::PlaceholderOutput);
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("\"from\""), "None from should be omitted: {json}");
        assert!(!json.contains("\"bytes\""), "None bytes should be omitted: {json}");
        assert!(!json.contains("\"blake3\""), "None blake3 should be omitted: {json}");
    }

    #[tokio::test]
    async fn append_creates_file_and_writes_jsonl() {
        let dir = tempdir().unwrap();
        let journal = AssetStatusJournal::new(dir.path().join("cloud/status.jsonl"));

        let event = AssetStatusEvent {
            at: Utc::now(),
            asset: "svc:model.bin".to_string(),
            from: Some(AssetState::PinnedNotPublished),
            to: AssetState::Published,
            bytes: Some(512),
            blake3: Some("deafbeef".to_string()),
        };
        journal.append(&event).await;

        let content = tokio::fs::read_to_string(journal.path()).await.unwrap();
        assert!(!content.is_empty(), "journal file must be non-empty after append");
        let parsed: AssetStatusEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.asset, event.asset);
        assert_eq!(parsed.to, AssetState::Published);
    }

    #[tokio::test]
    async fn replay_empty_when_no_file() {
        let dir = tempdir().unwrap();
        let journal = AssetStatusJournal::new(dir.path().join("cloud/status.jsonl"));
        let map = journal.last_state_per_asset().await;
        assert!(map.is_empty(), "missing journal → empty map");
    }

    #[tokio::test]
    async fn replay_yields_last_state_per_asset() {
        let dir = tempdir().unwrap();
        let journal = AssetStatusJournal::new(dir.path().join("cloud/status.jsonl"));
        let asset = "svc:model.bin";

        journal
            .append(&AssetStatusEvent {
                at: Utc::now(),
                asset: asset.to_string(),
                from: Some(AssetState::PinnedNotPublished),
                to: AssetState::Published,
                bytes: None,
                blake3: None,
            })
            .await;
        journal
            .append(&AssetStatusEvent {
                at: Utc::now(),
                asset: asset.to_string(),
                from: Some(AssetState::Published),
                to: AssetState::DriftBucket,
                bytes: None,
                blake3: None,
            })
            .await;

        let map = journal.last_state_per_asset().await;
        assert_eq!(map.get(asset), Some(&AssetState::DriftBucket));
    }

    #[tokio::test]
    async fn replay_tracks_multiple_assets_independently() {
        let dir = tempdir().unwrap();
        let journal = AssetStatusJournal::new(dir.path().join("cloud/status.jsonl"));

        journal.append(&sample_event("svc:a.bin", AssetState::Published)).await;
        journal.append(&sample_event("svc:b.bin", AssetState::PinnedNotPublished)).await;
        journal.append(&sample_event("svc:a.bin", AssetState::DriftBucket)).await;

        let map = journal.last_state_per_asset().await;
        assert_eq!(map.get("svc:a.bin"), Some(&AssetState::DriftBucket));
        assert_eq!(map.get("svc:b.bin"), Some(&AssetState::PinnedNotPublished));
    }

    #[tokio::test]
    async fn replay_skips_blank_lines_without_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("status.jsonl");
        // Write a valid line, a blank, and another valid line.
        let valid = serde_json::to_string(&sample_event("svc:x.bin", AssetState::Published))
            .unwrap()
            + "\n";
        tokio::fs::write(&path, format!("{valid}\n{valid}")).await.unwrap();
        let journal = AssetStatusJournal::new(path);
        let map = journal.last_state_per_asset().await;
        assert_eq!(map.get("svc:x.bin"), Some(&AssetState::Published));
    }

    #[tokio::test]
    async fn subscribe_receives_appended_events() {
        let dir = tempdir().unwrap();
        let journal = AssetStatusJournal::new(dir.path().join("cloud/status.jsonl"));
        let mut rx = journal.subscribe();

        let event = sample_event("svc:w.bin", AssetState::Published);
        journal.append(&event).await;

        let received = rx.try_recv().expect("event must be received");
        assert_eq!(received.asset, event.asset);
        assert_eq!(received.to, AssetState::Published);
    }
}
