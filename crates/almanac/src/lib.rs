pub mod coalesce;
pub mod config;
pub mod feed;
pub mod gh;
pub mod issues_feed;
pub mod issues_source;
pub mod r2;
pub mod receiver;
pub mod runner;
pub mod serve;
pub mod sink;
pub mod sources;

pub use config::{
    ConfigError, EmitConfig, FeedConfig, FeedDef, FeedLoader, OnChangeConfig, SourceConfig,
    TriggerConfig,
};
pub use feed::{Release, ReleaseAsset, ReleaseFeed};
pub use workload_spec::{BlakeHash, License};
pub use issues_feed::{ArtifactSink, Issue, IssuesFeed, OnChange, RevalidateRequest};
pub use issues_source::IssuesSource;
pub use receiver::{router as receiver_router, MirrorBind, RevalidateTx};
pub use serve::{run, serve_receiver, serve_receiver_on, ServeConfig};
pub use runner::{FeedRunner, RunResult, RunnerError};
pub use sink::{FeedSink, SinkError, SinkTarget};
pub use sources::{ReleaseSource, SourceError};
