//! R090-F6 — `MeshResolver` trait contract tests.
//!
//! Round-trips `EnvValue::FromMesh` through serde and exercises the trait's
//! happy + missing-ident error paths against a `FakeMeshResolver`. Warden's
//! own resolver lives in `warden::deploy::mesh_resolve` and has its own
//! integration tests (Url/Host/Port + waiting-for-dep + timeout).

use std::collections::HashMap;

use workload_spec::validate::{resolve_env_from_mesh, MeshError, MeshResolver};
use workload_spec::*;

// ── Fake resolver ─────────────────────────────────────────────────────────────

/// Test resolver backed by an in-memory ident → ports map.
struct FakeMeshResolver {
    by_ident: HashMap<String, Vec<u16>>,
}

impl FakeMeshResolver {
    fn new() -> Self {
        Self {
            by_ident: HashMap::new(),
        }
    }

    fn with(mut self, ident: &str, ports: Vec<u16>) -> Self {
        self.by_ident.insert(ident.into(), ports);
        self
    }
}

impl MeshResolver for FakeMeshResolver {
    fn resolve(&self, ident: &MeshIdent, kind: MeshLookup) -> Result<String, MeshError> {
        let ports = self
            .by_ident
            .get(&ident.0)
            .ok_or_else(|| MeshError::NotDeployed {
                ident: ident.0.clone(),
            })?;
        match kind {
            MeshLookup::Host => Ok(ident.0.clone()),
            MeshLookup::Port => {
                let p = ports.first().ok_or(MeshError::NoPorts {
                    ident: ident.0.clone(),
                    lookup: kind,
                })?;
                Ok(p.to_string())
            }
            MeshLookup::Url => {
                let p = ports.first().ok_or(MeshError::NoPorts {
                    ident: ident.0.clone(),
                    lookup: kind,
                })?;
                Ok(format!("http://{}:{}", ident.0, p))
            }
        }
    }
}

// ── Round-trip ────────────────────────────────────────────────────────────────

#[test]
fn from_mesh_round_trips_through_serde() {
    let original = EnvValue::FromMesh {
        ident: MeshIdent("noisetable-db.pdx".into()),
        kind: MeshLookup::Url,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let back: EnvValue = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, back);
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn url_renders_first_port_with_http_prefix() {
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432, 9100]);
    let value = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Url)
        .expect("resolve");
    assert_eq!(value, "http://noisetable-db.pdx:5432");
}

#[test]
fn host_renders_bare_ident() {
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432]);
    let value = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Host)
        .expect("resolve");
    assert_eq!(value, "noisetable-db.pdx");
}

#[test]
fn port_renders_first_port_as_string() {
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432, 9100]);
    let value = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Port)
        .expect("resolve");
    assert_eq!(value, "5432");
}

// ── Error paths ───────────────────────────────────────────────────────────────

#[test]
fn missing_ident_returns_not_deployed_error() {
    let resolver = FakeMeshResolver::new(); // empty map
    let err = resolver
        .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Url)
        .unwrap_err();
    assert_eq!(
        err,
        MeshError::NotDeployed {
            ident: "noisetable-db.pdx".into(),
        }
    );
}

#[test]
fn deployed_but_no_ports_returns_no_ports_error() {
    let resolver = FakeMeshResolver::new().with("portless.pdx", vec![]);
    let err = resolver
        .resolve(&MeshIdent("portless.pdx".into()), MeshLookup::Url)
        .unwrap_err();
    assert_eq!(
        err,
        MeshError::NoPorts {
            ident: "portless.pdx".into(),
            lookup: MeshLookup::Url,
        }
    );
}

// ── resolve_env_from_mesh helper ──────────────────────────────────────────────

#[test]
fn resolve_env_from_mesh_renders_only_from_mesh_entries() {
    let env = vec![
        EnvVar {
            name: "APP_ENV".into(),
            value: EnvValue::Literal {
                value: "production".into(),
            },
        },
        EnvVar {
            name: "DB_PASSWORD".into(),
            value: EnvValue::FromSecret {
                secret: "creds".into(),
                key: "password".into(),
            },
        },
        EnvVar {
            name: "DATABASE_URL".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("noisetable-db.pdx".into()),
                kind: MeshLookup::Url,
            },
        },
        EnvVar {
            name: "DATABASE_HOST".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("noisetable-db.pdx".into()),
                kind: MeshLookup::Host,
            },
        },
    ];
    let resolver = FakeMeshResolver::new().with("noisetable-db.pdx", vec![5432]);

    let resolved = resolve_env_from_mesh(&env, &resolver).expect("resolve env");

    assert_eq!(resolved.len(), 4);
    // Literal pass-through
    assert_eq!(
        resolved[0].value,
        EnvValue::Literal {
            value: "production".into()
        }
    );
    // FromSecret untouched — secrets layer (R090-F5) handles those
    assert!(matches!(resolved[1].value, EnvValue::FromSecret { .. }));
    // FromMesh now Literal
    assert_eq!(
        resolved[2].value,
        EnvValue::Literal {
            value: "http://noisetable-db.pdx:5432".into()
        }
    );
    assert_eq!(
        resolved[3].value,
        EnvValue::Literal {
            value: "noisetable-db.pdx".into()
        }
    );
}

#[test]
fn resolve_env_from_mesh_propagates_missing_ident_error() {
    let env = vec![EnvVar {
        name: "DATABASE_URL".into(),
        value: EnvValue::FromMesh {
            ident: MeshIdent("missing.pdx".into()),
            kind: MeshLookup::Url,
        },
    }];
    let resolver = FakeMeshResolver::new(); // no idents registered

    let err = resolve_env_from_mesh(&env, &resolver).unwrap_err();
    assert_eq!(
        err,
        MeshError::NotDeployed {
            ident: "missing.pdx".into(),
        }
    );
}
