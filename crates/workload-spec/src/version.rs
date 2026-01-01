use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Wire-format schema version envelope.
///
/// Single variant today. When a breaking field rename or removal requires a
/// migration path, a new variant is added. The `schema_version` field on
/// `WorkloadSpec` uses this as a tag so rolling clusters can decode multiple
/// versions simultaneously. See arch doc §Evolution for the versioning rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub enum SchemaVersion {
    V1,
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::V1
    }
}
