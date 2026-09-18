//! Strip resolved secret VALUES out of a [`Workload`] before it is served on
//! yubaba's read path (R876-B13).
//!
//! ## Why this exists
//!
//! `GET /workloads/{ident}/spec` answers with the envelope kamaji is
//! supervising, and that envelope carries **materialised** secrets by design:
//! kamaji's `validate_spec_for_constable()` refuses a spec still holding
//! [`EnvValue::FromSecret`] / [`EnvValue::FromMesh`], so yubaba's admission has
//! to resolve every one of them into a literal before handing the spec over.
//! The route is unauthenticated — `correlation_id_layer` is the only middleware
//! on that router — so serialising the envelope verbatim serves live
//! credentials to anything that can reach the mesh address. That was observed
//! on 2026-09-11: a `mesofact-static` workload's `revalidate_receiver.env`
//! block came back holding a Cloudflare API token and an S3 access-key pair as
//! plain strings.
//!
//! ## What it keeps, and why that is the whole point
//!
//! The route's stated purpose is "what variables, mounts and annotations does
//! the running workload have, so a full-replace deploy does not drop them".
//! That purpose is served by **names and shape**, not by values: every key
//! survives, every mount, path, port, digest and annotation survives, and only
//! the value side of a value channel becomes [`REDACTED`].
//!
//! An [`EnvValue::FromSecret`] is left **intact**, because it is already a
//! reference — `{secret, key}` is a vault slot NAME, and serving the name is
//! strictly more useful than serving nothing. Provenance only disappears once
//! yubaba has resolved the reference, and at that point a resolved literal is
//! indistinguishable from an ordinary one. There is deliberately no heuristic
//! for telling them apart: a "does this look like a credential" guess leaks the
//! one it gets wrong, so every literal is redacted.
//!
//! The placeholder is fixed and carries no information about what it replaced —
//! no hash, no prefix, no length. A truncated hash of a short credential is
//! still an oracle.
//!
//! ## Pre-1.0 break, not a flag
//!
//! This changes the response shape for every caller; there is no
//! `?include_secrets=` escape hatch and no un-redacted variant beside it. The
//! only in-tree consumer is `crates/yah/cloud-client`'s `get_workload_spec`,
//! read by `app/yah/cli/src/cloud.rs`'s passway read-back guard, which asks
//! whether an env var NAME is present — unaffected. Nothing round-trips a read
//! spec back into a deploy.
//!
//! ## Residual, stated rather than guessed
//!
//! Free-form argv (`WorkloadSpec::command` / `entrypoint`,
//! `AlmanacManifest::command`), URLs ([`workload_spec::AlmanacTarget::Http`],
//! [`workload_spec::FetchSource::url`]), `labels` and `annotations` are NOT
//! redacted: none of them is a secret channel by design, all of them are
//! load-bearing for the route's purpose, and redacting them would blind the
//! caller to the shape it came to read. An operator who pastes a credential
//! into an argv still leaks it here. The real answer to that is the structural
//! fix — kamaji resolving from the vault at container-start so the envelope
//! never holds a value at all.

use workload_spec::{
    ContainerManifest, EnvValue, MesofactStaticWorkload, TenantPasswayWorkload, Workload,
    WorkloadSpec,
};

/// What every redacted value is replaced with. Fixed, non-reversible, and
/// identical for every field so it leaks neither the value nor its length.
pub const REDACTED: &str = "[redacted]";

/// Redact every resolved secret value in `w` in place, leaving names and shape
/// untouched.
///
/// Exhaustive over [`Workload`]'s variants on purpose: a new variant is a
/// compile error here rather than a silent new way to serve a credential.
pub fn redact_for_read(w: &mut Workload) {
    match w {
        Workload::Container(manifest) => match manifest {
            ContainerManifest::Reference(spec) => redact_workload_spec(spec),
            ContainerManifest::Recipe(build) => {
                redact_string_env(&mut build.run.env);
            }
        },
        Workload::MesofactStatic(m) => redact_mesofact_static(m),
        Workload::Almanac(_) => {
            // `AlmanacManifest` is a command, a cadence and reachability
            // targets — no value channel. Its `command` is free-form argv; see
            // the module residual note.
        }
        Workload::StaticAsset(_) => {
            // Filenames, blake3 digests and fetch URLs. No resolved secret
            // travels here.
        }
        Workload::TenantPassway(p) => redact_tenant_passway(p),
    }
}

/// The container spec's two value channels: `env` and inline file bodies.
///
/// Deliberately kept: `secrets` (a [`workload_spec::SecretMount`] is a
/// reference — a store path or a cluster slot name — and never the material),
/// `volumes`, `expose`, `labels`, `annotations`, `image`, `resources`.
fn redact_workload_spec(spec: &mut WorkloadSpec) {
    for var in &mut spec.env {
        redact_env_value(&mut var.value);
    }
    for file in &mut spec.files {
        // `InlineFile.content` is a whole file body carried in the clear. The
        // path and mode are the shape; the bytes are the value.
        file.content = REDACTED.to_string();
    }
}

/// `EnvValue::Literal` is the resolved form and is redacted; the two reference
/// forms are names, not values, and are served as-is.
///
/// Exhaustive on purpose — a new `EnvValue` variant must be classified here
/// rather than default to being served.
fn redact_env_value(v: &mut EnvValue) {
    match v {
        EnvValue::Literal { value } => *value = REDACTED.to_string(),
        EnvValue::FromSecret { .. } | EnvValue::FromMesh { .. } => {}
    }
}

/// A `BTreeMap<String, String>` env block: every key survives, every value goes.
fn redact_string_env(env: &mut std::collections::BTreeMap<String, String>) {
    for value in env.values_mut() {
        *value = REDACTED.to_string();
    }
}

/// The variant the live exposure was found on. `revalidate_receiver.env` is
/// documented as "resolved from the keystore at deploy time — the node never
/// sees slot names", which is exactly the shape this ticket is about.
///
/// Deliberately kept: `publish_config` and `routes` (paths/route names, not
/// content), `build`, `digest`, `runtime`, `port`, `origin`, `mirror_key_env`
/// (an env var NAME).
fn redact_mesofact_static(m: &mut MesofactStaticWorkload) {
    if let Some(ssr) = m.ssr_runtime.as_mut() {
        redact_workload_spec(ssr);
    }
    if let Some(bundle) = m.serve_bundle.as_mut() {
        redact_string_env(&mut bundle.env);
    }
    if let Some(recv) = m.revalidate_receiver.as_mut() {
        redact_string_env(&mut recv.env);
        for feed in &mut recv.feeds {
            // `config_toml` is a verbatim feed-definition file body travelling
            // by value — the same channel as `InlineFile.content`. The feed
            // `name` is the shape.
            feed.config_toml = REDACTED.to_string();
        }
    }
}

/// Deliberately kept: `tls.cert` / `tls.key` are node-side PEM **paths**, not
/// material (see [`workload_spec::TenantPasswayTls`]), and `upstreams` /
/// `domain` / `listen` are addresses.
fn redact_tenant_passway(p: &mut TenantPasswayWorkload) {
    redact_string_env(&mut p.env);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// The sentinel stands in for a live credential. Every assertion below is
    /// value-shaped — "these bytes are not in the JSON" — rather than
    /// field-shaped, so reshaping the spec cannot make one pass vacuously.
    const SECRET: &str = "SENTINEL-live-credential-4f1c9a";

    fn json(w: &Workload) -> String {
        serde_json::to_string(w).expect("a Workload serialises")
    }

    /// A minimal, shape-valid container spec — the same fixture shape
    /// `tests/integration_deploy_through_kamaji.rs` uses.
    fn container_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
            name: name.to_string(),
            image: workload_spec::ImageRef {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
                tag: "latest".into(),
                digest: workload_spec::ImageRef::UNPINNED_DIGEST.to_string(),
            },
            tier: workload_spec::TierTag("private".into()),
            tenant: workload_spec::TenantId::singleton(),
            namespace: workload_spec::NamespaceId::singleton(),
            replicas: 1,
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            files: vec![],
            volumes: vec![],
            resources: workload_spec::ResourceLimits {
                memory_mb: 64,
                cpu_millis: 128,
                memory_request_mb: None,
                cpu_limit_millis: None,
                pids_max: None,
                scratch_floor_mb: None,
            },
            depends_on: vec![],
            requires: vec![],
            healthcheck: None,
            restart_policy: workload_spec::RestartPolicy::Always,
            archetype: None,
            stop_policy: workload_spec::StopPolicy {
                signal: 15,
                grace_period: workload_spec::Millis::from_secs(5),
            },
            expose: workload_spec::ExposeSpec {
                mesh: workload_spec::MeshExpose {
                    identity: workload_spec::MeshIdent(name.to_string()),
                    ports: workload_spec::MeshExpose::anonymous_ports([8080]),
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            durability: None,
            annotations: Default::default(),
        }
    }

    fn mesofact_with_secrets() -> Workload {
        let mut env = BTreeMap::new();
        env.insert("CLOUDFLARE_API_TOKEN".to_string(), SECRET.to_string());
        env.insert("MESOFACT_S3_SECRET_ACCESS_KEY".to_string(), SECRET.to_string());
        Workload::MesofactStatic(MesofactStaticWorkload {
            build: workload_spec::BuildConfig {
                command: Some("bun run build".into()),
                out_dir: std::path::PathBuf::from("dist"),
                render_command: None,
            },
            routes: std::path::PathBuf::from("./mesofact.routes.ts"),
            build_mode: workload_spec::BuildMode::default(),
            ssr_runtime: None,
            serve_bundle: Some(workload_spec::MesofactServeBundle {
                digest: workload_spec::BlakeHash("a".repeat(64)),
                runtime: "self".into(),
                lifecycle: workload_spec::BundleLifecycle::KeepAlive,
                port: Some(8080),
                env: env.clone(),
                origin: None,
            }),
            revalidate_receiver: Some(workload_spec::MesofactRevalidateReceiver {
                routes: vec!["/".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: Some("MESOFACT_MIRROR_KEY".into()),
                env,
                feeds: vec![workload_spec::AlmanacFeed {
                    name: "releases".into(),
                    config_toml: format!("token = \"{SECRET}\"\n"),
                }],
                feed_runtime: None,
                feed_interval_secs: 300,
                feed_project_prefix: None,
                secrets: vec![],
            }),
        })
    }

    #[test]
    fn a_mesofact_workloads_resolved_env_values_do_not_survive_redaction() {
        let mut w = mesofact_with_secrets();
        assert!(
            json(&w).contains(SECRET),
            "test precondition: the fixture must actually carry the secret, or \
             the assertion below passes vacuously"
        );

        redact_for_read(&mut w);
        let out = json(&w);

        assert!(
            !out.contains(SECRET),
            "a resolved secret survived redaction: {out}"
        );
        // The names are the payload the route exists to serve — they must NOT
        // have been redacted along with the values.
        assert!(out.contains("CLOUDFLARE_API_TOKEN"), "{out}");
        assert!(out.contains("MESOFACT_S3_SECRET_ACCESS_KEY"), "{out}");
        assert!(out.contains("MESOFACT_MIRROR_KEY"), "{out}");
        assert!(out.contains("releases"), "the feed name is shape: {out}");
        assert!(out.contains("mesofact.config.toml"), "{out}");
    }

    #[test]
    fn a_container_specs_literal_env_and_inline_files_are_redacted_by_value() {
        let mut spec = container_spec("redact-probe");
        spec.env = vec![
            workload_spec::EnvVar {
                name: "DATABASE_URL".into(),
                value: EnvValue::Literal {
                    value: format!("postgres://u:{SECRET}@db/x"),
                },
            },
            workload_spec::EnvVar {
                name: "R2_KEY".into(),
                value: EnvValue::FromSecret {
                    secret: "cloudflare-r2-secret-key".into(),
                    key: "value".into(),
                },
            },
        ];
        spec.files = vec![workload_spec::InlineFile {
            path: std::path::PathBuf::from("/etc/app/config.toml"),
            content: format!("api_token = \"{SECRET}\"\n"),
            mode: Some(0o600),
        }];
        let mut w = Workload::Container(ContainerManifest::Reference(spec));
        assert!(json(&w).contains(SECRET), "test precondition");

        redact_for_read(&mut w);
        let out = json(&w);

        assert!(!out.contains(SECRET), "a resolved secret survived: {out}");
        assert!(out.contains("DATABASE_URL"), "{out}");
        assert!(out.contains("/etc/app/config.toml"), "the path is shape: {out}");
        // An UNRESOLVED reference is a slot name, not a value — serving it is
        // the better answer and it must be left alone.
        assert!(
            out.contains("cloudflare-r2-secret-key"),
            "a FromSecret reference is a name and must survive: {out}"
        );
    }

    #[test]
    fn the_placeholder_leaks_neither_the_value_nor_its_length() {
        let mut short = container_spec("short");
        short.env = vec![workload_spec::EnvVar {
            name: "A".into(),
            value: EnvValue::Literal { value: "x".into() },
        }];
        let mut long = container_spec("short");
        long.env = vec![workload_spec::EnvVar {
            name: "A".into(),
            value: EnvValue::Literal {
                value: "x".repeat(4096),
            },
        }];
        let mut a = Workload::Container(ContainerManifest::Reference(short));
        let mut b = Workload::Container(ContainerManifest::Reference(long));
        redact_for_read(&mut a);
        redact_for_read(&mut b);
        assert_eq!(
            json(&a),
            json(&b),
            "two different values must redact to byte-identical output, or the \
             response is a length oracle"
        );
    }
}
