use async_trait::async_trait;

use crate::issues_feed::Issue;
use crate::sources::SourceError;

/// Fetch the current issue list from the authoritative in-process store.
///
/// The only production implementation is `InProcessIssues` in `issue-tracker`
/// (R443-F7), which wraps an `Arc<IssueStore>`. Almanac stays storage-agnostic
/// and turso-free — no file path, no separate process.
#[async_trait]
pub trait IssuesSource: Send + Sync {
    async fn list(&self) -> Result<Vec<Issue>, SourceError>;
}
