pub mod coalesce;
pub mod config;
pub mod feed;
pub mod fetch;
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
    ConfigError, CredentialRef, EmitConfig, FeedConfig, FeedDef, FeedLoader, OnChangeConfig,
    SourceConfig, TriggerConfig,
};
pub use feed::{
    untyped_hash_fields, AssetHash, HashAlgo, HashParseError, Release, ReleaseAsset, ReleaseFeed,
    Sha256Hash, LEGACY_BARE_HEX_PATHS,
};
pub use workload_spec::{BlakeHash, License};
pub use issues_feed::{ArtifactSink, Issue, IssuesFeed, OnChange, RevalidateRequest};
pub use issues_source::IssuesSource;
pub use fetch::{
    poke_for, project_relative_artifact, route_of, FeedFetcher, FeedOutcome, HttpPoke, NoPoke,
    Poke, PokeInputs, RevalidatePoke,
};
pub use r2::{
    feed_from_channel_manifest, feed_from_index_manifest, feed_from_source_manifest,
    feed_from_triples_manifest, ManifestError, R2Private,
};
pub use receiver::{router as receiver_router, MirrorBind, RevalidateTx};
pub use serve::{run, serve_receiver, serve_receiver_on, ServeConfig};
pub use runner::{FeedRunner, RunResult, RunnerError};
pub use sink::{FeedSink, SinkError, SinkTarget};
pub use sources::{FeedPayload, FeedSource, ReleaseSource, SourceError};
