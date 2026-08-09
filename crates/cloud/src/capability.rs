//! Service capabilities and the mirror-side driver bindings that satisfy them
//! (W265).
//!
//! The problem this solves: a `mesofact-static` component wants "somewhere to
//! put bytes that a browser can GET". At the dev tier that used to be a
//! disk-served directory, at sim it is MinIO over S3, at cloud it is R2. If the
//! *app* has to know which, it grows an `if dev { fs::write } else { s3_put }`
//! branch, and every later app inherits the same fork.
//!
//! So the app declares a tier-agnostic **capability** and the mirror declares
//! which **driver** implements it at this tier:
//!
//! ```text
//!   component kind  ──derives──▶  Capability  ◀──binds──  [drivers.<cap>] in mirrors/<env>.toml
//! ```
//!
//! # P1 scope
//!
//! Requirements are derived from the component `kind` — one match arm per kind,
//! zero per-service boilerplate, because every service in-tree today is
//! kind-implied. The explicit `[requires]` block in `service.toml` (for needs
//! that aren't kind-implied) and the binding-error surface ("service X needs s3,
//! mirror Y binds no s3 driver") are P2; see W265 §"Open follow-ups".

use crate::config::{MirrorConfig, MirrorProviderSlot};

/// A tier-agnostic thing a service needs, independent of who provides it.
///
/// Deliberately small: a capability earns a variant when a *second*
/// implementation of it exists at a different tier, because that is the moment
/// an app would otherwise have to fork. Pub/sub and secret-store are the
/// obvious next candidates and are not here yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// An S3-compatible object store. `local-s3-fs` at dev, `minio-container`
    /// at sim, `cloudflare-r2` at cloud/ha.
    S3,
    /// A PostgreSQL server reachable over pgwire. `local-pg-dev` at dev
    /// (R584-F1).
    ///
    /// Note what this is *not*: the camp's default store is service-owned
    /// libsql, embedded in the service process, and those services never touch
    /// this capability. `pg` is for non-rust services and rust services that
    /// specifically want the wire protocol.
    Pg,
}

impl Capability {
    /// The key this capability is declared under in `[drivers.<key>]`.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Pg => "pg",
        }
    }

    /// Capabilities implied by a component's `kind`.
    ///
    /// `kind` is a free-form string in `service.toml`, so an unknown kind maps
    /// to no capabilities rather than an error — a component kind this build
    /// doesn't know about is a forward-compat case, not a misconfiguration.
    pub fn for_component_kind(kind: &str) -> &'static [Capability] {
        match kind {
            // Everything that publishes bytes for a browser to fetch wants a
            // bucket with public read.
            "mesofact-static" | "mesofact-spa" | "static-asset" => &[Capability::S3],
            // No in-tree component kind implies pg today: the services that
            // want it are out-of-tree and non-mesofact, and they'll declare it
            // through P2's explicit `[requires]` block. The variant exists
            // because the *driver* ships now (R584-F1) — activation at P1 is
            // keyed off the mirror's `[drivers.pg]` binding, not off a kind.
            _ => &[],
        }
    }
}

impl MirrorConfig {
    /// The driver bound to `capability` in this mirror, if any.
    ///
    /// `None` means the tier declares no implementation. In P1 that's simply
    /// "this mirror doesn't use that capability"; P2's binding-error surface is
    /// what turns it into a diagnosable failure for a service that needs it.
    pub fn driver(&self, capability: Capability) -> Option<&MirrorProviderSlot> {
        self.drivers.get(capability.wire_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MirrorShape, Provider};

    fn mirror_with(toml_src: &str) -> MirrorConfig {
        toml::from_str(toml_src).expect("parse mirror")
    }

    #[test]
    fn static_shaped_kinds_imply_s3_and_nothing_else_does() {
        for kind in ["mesofact-static", "mesofact-spa", "static-asset"] {
            assert_eq!(
                Capability::for_component_kind(kind),
                &[Capability::S3],
                "{kind} should imply s3"
            );
        }
        for kind in [
            "cloudflare-worker",
            "mesofact-bundle",
            "not-a-real-kind",
            "",
        ] {
            assert!(
                Capability::for_component_kind(kind).is_empty(),
                "{kind} should imply nothing"
            );
        }
    }

    #[test]
    fn drivers_table_parses_and_resolves_by_capability() {
        let mirror = mirror_with(
            r#"
schema_version = 1
shape = "local"

[drivers.pg]
kind = "local-pg-dev"
"#,
        );
        assert!(matches!(mirror.shape, MirrorShape::Local));
        let slot = mirror.driver(Capability::Pg).expect("pg driver bound");
        assert_eq!(slot.inline_kind(), Some(Provider::LocalPgDev));
        assert!(mirror.driver(Capability::S3).is_none());
    }

    #[test]
    fn a_mirror_with_no_drivers_table_is_unchanged() {
        let mirror = mirror_with(
            r#"
schema_version = 1
shape = "local"

[providers.static]
kind = "local-static"
port = 4324
"#,
        );
        assert!(mirror.drivers.is_empty());
        assert!(mirror.driver(Capability::Pg).is_none());
        // …and round-trips without sprouting an empty `drivers` table.
        let back = toml::to_string(&mirror).expect("serialize");
        assert!(
            !back.contains("drivers"),
            "unexpected drivers table: {back}"
        );
    }
}
