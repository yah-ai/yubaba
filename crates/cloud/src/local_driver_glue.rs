//! Adapter between cloud's TOML-driven `ProviderConfig` shape and
//! [`local_driver::LocalContainerSpec`].
//!
//! Lives in the cloud crate (rather than `local-driver`) so the driver crate
//! stays decoupled from cloud's config types. Callers in cloud + yubaba that
//! need a [`LocalContainerSpec`] from a `kind = "local-container"` provider
//! TOML go through [`local_container_spec_from_provider`].

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use local_driver::{LocalContainerSpec, RuntimePref};

use crate::config::{Provider, ProviderConfig};

/// Parse a `kind = "local-container"` [`ProviderConfig`] into a
/// [`LocalContainerSpec`]. Rejects any other provider kind so the caller hits
/// a clean error rather than a confusing socket-missing message downstream.
pub fn local_container_spec_from_provider(p: &ProviderConfig) -> Result<LocalContainerSpec> {
    if !matches!(p.kind, Provider::LocalContainer) {
        bail!(
            "provider {id} has kind={kind:?}; LocalContainerSpec requires kind=\"local-container\"",
            id = p.id,
            kind = p.kind,
        );
    }
    let runtime = match p.fields.get("runtime").and_then(|v| v.as_str()) {
        Some(s) => RuntimePref::parse(s)?,
        None => RuntimePref::Auto,
    };
    let mut discovery = BTreeMap::new();
    if let Some(table) = p.fields.get("discovery").and_then(|v| v.as_table()) {
        for (k, v) in table.iter() {
            let s = v
                .as_str()
                .with_context(|| format!("provider {}: discovery.{k} must be a string", p.id))?;
            discovery.insert(k.clone(), PathBuf::from(s));
        }
    }
    let custom_docker_host = p
        .fields
        .get("custom_docker_host")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Ok(LocalContainerSpec {
        runtime,
        discovery,
        custom_docker_host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Provider, ProviderConfig};
    use local_driver::{
        canonical_label, canonical_name, ContainerRunSpec, ContainerState, DetectedRuntime,
        LocalRuntime,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    fn provider_orbstack_toml() -> ProviderConfig {
        let src = r#"
schema_version = 1
id = "orbstack"
kind = "local-container"
runtime = "auto"

[discovery]
orbstack = "~/.orbstack/run/docker.sock"
colima   = "~/.colima/default/docker.sock"
docker   = "/var/run/docker.sock"
"#;
        toml::from_str(src).unwrap()
    }

    #[test]
    fn spec_from_provider_config_picks_up_runtime_and_discovery() {
        let p = provider_orbstack_toml();
        let spec = local_container_spec_from_provider(&p).unwrap();
        assert_eq!(spec.runtime, RuntimePref::Auto);
        assert_eq!(spec.discovery.len(), 3);
        assert!(spec.discovery.contains_key("orbstack"));
        assert!(spec.discovery.contains_key("colima"));
        assert!(spec.discovery.contains_key("docker"));
        assert!(spec.custom_docker_host.is_none());
    }

    #[test]
    fn spec_from_provider_config_defaults_runtime_to_auto() {
        let src = r#"
schema_version = 1
id = "orbstack"
kind = "local-container"
"#;
        let p: ProviderConfig = toml::from_str(src).unwrap();
        let spec = local_container_spec_from_provider(&p).unwrap();
        assert_eq!(spec.runtime, RuntimePref::Auto);
        assert!(spec.discovery.is_empty(), "no discovery table → empty map");
        assert!(spec.custom_docker_host.is_none());
    }

    #[test]
    fn spec_from_provider_config_parses_custom_docker_host() {
        let src = r#"
schema_version = 1
id = "custom"
kind = "local-container"
runtime = "custom"
custom_docker_host = "tcp://localhost:2375"
"#;
        let p: ProviderConfig = toml::from_str(src).unwrap();
        let spec = local_container_spec_from_provider(&p).unwrap();
        assert_eq!(spec.runtime, RuntimePref::Custom);
        assert_eq!(
            spec.custom_docker_host.as_deref(),
            Some("tcp://localhost:2375")
        );
    }

    #[test]
    fn spec_rejects_non_local_container_provider() {
        let p = ProviderConfig {
            schema_version: 1,
            id: "cloudflare".into(),
            kind: Provider::Cloudflare,
            credentials: None,
            fields: BTreeMap::new(),
        };
        let err = local_container_spec_from_provider(&p)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Cloudflare"),
            "error should name the wrong kind, got: {err}"
        );
    }

    #[test]
    fn spec_rejects_bad_runtime_value() {
        let src = r#"
schema_version = 1
id = "orbstack"
kind = "local-container"
runtime = "nonsense-runtime"
"#;
        let p: ProviderConfig = toml::from_str(src).unwrap();
        let err = local_container_spec_from_provider(&p)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("nonsense-runtime"),
            "error should name the bad value, got: {err}"
        );
    }

    #[test]
    fn spec_rejects_non_string_discovery_value() {
        let src = r#"
schema_version = 1
id = "orbstack"
kind = "local-container"

[discovery]
orbstack = 42
"#;
        let p: ProviderConfig = toml::from_str(src).unwrap();
        let err = local_container_spec_from_provider(&p)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("orbstack"),
            "error should name the bad key, got: {err}"
        );
    }

    // ── live integration tests (require a reachable docker socket) ───────────

    async fn detect_live() -> Option<LocalRuntime> {
        let p = provider_orbstack_toml();
        let spec = local_container_spec_from_provider(&p).ok()?;
        LocalRuntime::detect(&spec).await.ok()
    }

    #[tokio::test]
    #[ignore = "requires docker socket (orbstack/colima/docker running)"]
    async fn image_cache_skip_pull_when_present() {
        let Some(runtime) = detect_live().await else {
            eprintln!("SKIP: no docker socket reachable");
            return;
        };
        let pulled_first = runtime.ensure_image("hello-world:latest").await.unwrap();
        let pulled_second = runtime.ensure_image("hello-world:latest").await.unwrap();
        assert!(
            !pulled_second,
            "second ensure_image should skip the pull (cache hit); pulled_first={pulled_first}",
        );
    }

    #[tokio::test]
    #[ignore = "requires docker socket"]
    async fn run_stop_lifecycle_is_idempotent() {
        let Some(runtime) = detect_live().await else {
            eprintln!("SKIP: no docker socket reachable");
            return;
        };
        runtime.ensure_image("alpine:3.20").await.unwrap();
        let spec = ContainerRunSpec {
            name: canonical_name("itest", "test", "sleeper"),
            image: "alpine:3.20".into(),
            label: canonical_label("itest", "test", "sleeper"),
            ports: vec![],
            env: BTreeMap::new(),
            volumes: vec![],
            cmd: vec!["sleep".into(), "30".into()],
            cap_add: vec![],
            cgroupns: None,
            network: None,
            network_aliases: vec![],
        };
        runtime.run(&spec).await.unwrap();
        let state = runtime.container_state(&spec.name).await.unwrap();
        assert_eq!(state, Some(ContainerState::Running));
        runtime.run(&spec).await.unwrap();
        let state = runtime.container_state(&spec.name).await.unwrap();
        assert_eq!(state, Some(ContainerState::Running));
        let owned = runtime.list_owned().await.unwrap();
        assert!(owned.iter().any(|c| c.name == spec.name));
        runtime
            .stop_and_remove(&spec.name, Duration::from_secs(2))
            .await
            .unwrap();
        let state = runtime.container_state(&spec.name).await.unwrap();
        assert_eq!(state, None);
        // Path-only fixture suppresses "unused" warning on platforms without a socket.
        let _ = PathBuf::new();
        let _ = DetectedRuntime::Orbstack;
    }
}
