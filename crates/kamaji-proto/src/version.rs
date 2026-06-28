use serde::{Deserialize, Serialize};

/// Wire protocol version. Bumped on any backward-incompatible change to the
/// message enums.
///
/// Both peers exchange [`crate::WardenToConstable::Hello`] /
/// [`crate::ConstableToWarden::Welcome`] at connection start so a rolling
/// cluster can decode multiple versions during upgrades — the receiver picks
/// the highest version it supports that the sender also offers.
///
/// V1 is the initial scaffolding shape. Add a V2 variant when a breaking
/// rename or removal lands; additive variant introductions (new request kinds,
/// new ack kinds) ride on the `#[non_exhaustive]` enums without a version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProtocolVersion {
    V1,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl ProtocolVersion {
    /// The version this build of `kamaji-proto` produces by default.
    pub const CURRENT: Self = Self::V1;
}
