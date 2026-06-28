//! Build the W193 workspace asset-status report as a `serde_json::Value`
//! suitable for `cloud.status` RPC responses (R470-T4).
//!
//! Shared between the CLI (`yah cloud status --json`) and the camp-socket
//! `cloud.status` handler so both surfaces return bit-identical JSON.

use std::collections::HashMap;
use std::path::Path;

use crate::app_manifest::{discover_app_manifests, HostContext};
use crate::asset_journal::{AssetState, AssetStatusEvent};
use crate::config::CloudConfig;

/// Build the W193 JSON status report.
///
/// - `filter_services`: when non-empty, only services whose name is in the
///   slice are included in the services array. Apps are filtered by whether
///   their deps resolve into those services.
/// - `filter_app`: when `Some`, only the named app appears in the apps array.
///
/// Returns the JSON value directly (cheap to clone, cheap for callers to embed
/// in larger responses). Never fails — missing files are silently skipped.
pub fn build_status_json(
    workspace_root: &Path,
    filter_services: &[String],
    filter_app: Option<&str>,
) -> serde_json::Value {
    // 1. Load cloud config for the services list.
    let cfg = match CloudConfig::load(workspace_root) {
        Ok(c) => c,
        Err(_) => return empty_report(workspace_root),
    };

    // 2. Replay the journal.
    let journal_path = crate::paths::asset_status_journal(workspace_root);
    let events = replay_last_events(&journal_path);

    // 3. Walk services → static-asset components → workload.toml.
    let only: std::collections::BTreeSet<&str> =
        filter_services.iter().map(String::as_str).collect();

    // alias → (service_name, filename)
    let mut alias_to_asset: HashMap<String, (String, String)> = HashMap::new();
    // (service_name, component_id, assets, aliases)
    let mut components: Vec<(
        String,
        String,
        Vec<workload_spec::AssetEntry>,
        std::collections::BTreeMap<String, String>,
    )> = Vec::new();

    for (svc_name, svc) in &cfg.services {
        if !only.is_empty() && !only.contains(svc_name.as_str()) {
            continue;
        }
        for component in &svc.service.components {
            if component.kind != "static-asset" {
                continue;
            }
            let workload_path = workspace_root.join(&component.path).join("workload.toml");
            let src = match std::fs::read_to_string(&workload_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let workload: workload_spec::Workload = match toml::from_str(&src) {
                Ok(w) => w,
                Err(_) => continue,
            };
            if let workload_spec::Workload::StaticAsset(saw) = workload {
                for (alias, filename) in &saw.aliases {
                    alias_to_asset.insert(alias.clone(), (svc_name.clone(), filename.clone()));
                }
                components.push((
                    svc_name.clone(),
                    component.id.clone(),
                    saw.assets,
                    saw.aliases,
                ));
            }
        }
    }

    // 4. Discover app manifests.
    let app_manifests = discover_app_manifests(workspace_root).unwrap_or_default();
    let host_ctx = HostContext::current();

    // 5. Reverse map: (service, filename) → Vec<"app@alias">.
    let mut consumers_map: HashMap<(String, String), Vec<String>> = HashMap::new();
    for (_, manifest) in &app_manifests {
        for dep in &manifest.asset_deps {
            if let Some((svc, filename)) = alias_to_asset.get(&dep.alias) {
                consumers_map
                    .entry((svc.clone(), filename.clone()))
                    .or_default()
                    .push(format!("{}@{}", manifest.name, dep.alias));
            }
        }
    }

    // 6. Build services array (grouped by service name).
    let mut service_map: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();

    for (svc_name, component_id, assets, _) in &components {
        let asset_arr: Vec<serde_json::Value> = assets
            .iter()
            .map(|entry| {
                let journal_key = format!("{svc_name}:{}", entry.filename);
                let (state, bytes, last_reconciled_at) = match events.get(&journal_key) {
                    Some(ev) => (ev.to, ev.bytes, Some(ev.at)),
                    None => (infer_state(entry), None, None),
                };
                let consumers = consumers_map
                    .get(&(svc_name.clone(), entry.filename.clone()))
                    .cloned()
                    .unwrap_or_default();

                let mut obj = serde_json::json!({
                    "filename": entry.filename,
                    "state": serde_json::to_value(state).unwrap_or(serde_json::Value::Null),
                    "consumers": consumers,
                });
                if let Some(b) = bytes {
                    obj["bytes"] = serde_json::json!(b);
                }
                if let Some(t) = last_reconciled_at {
                    obj["last_reconciled_at"] = serde_json::json!(t.to_rfc3339());
                }
                obj
            })
            .collect();

        service_map
            .entry(svc_name.clone())
            .or_default()
            .push(serde_json::json!({
                "id": component_id,
                "kind": "static-asset",
                "assets": asset_arr,
            }));
    }

    let services_arr: Vec<serde_json::Value> = service_map
        .into_iter()
        .map(|(svc, comps)| serde_json::json!({ "service": svc, "components": comps }))
        .collect();

    // 7. Build apps array.
    let apps_arr: Vec<serde_json::Value> = app_manifests
        .iter()
        .filter(|(_, manifest)| filter_app.map_or(true, |name| manifest.name == name))
        .map(|(_, manifest)| {
            let deps: Vec<serde_json::Value> = manifest
                .asset_deps
                .iter()
                .map(|dep| {
                    let required_here = dep.required_here(&host_ctx);
                    let state_val = alias_to_asset
                        .get(&dep.alias)
                        .map(|(svc, filename)| {
                            let key = format!("{svc}:{filename}");
                            events
                                .get(&key)
                                .map(|ev| {
                                    serde_json::to_value(ev.to).unwrap_or(serde_json::Value::Null)
                                })
                                .unwrap_or_else(|| {
                                    // Infer from catalog.
                                    components
                                        .iter()
                                        .find(|(s, _, assets, _)| {
                                            s == svc
                                                && assets.iter().any(|a| &a.filename == filename)
                                        })
                                        .and_then(|(_, _, assets, _)| {
                                            assets.iter().find(|a| &a.filename == filename)
                                        })
                                        .map(|entry| {
                                            serde_json::to_value(infer_state(entry))
                                                .unwrap_or(serde_json::Value::Null)
                                        })
                                        .unwrap_or(serde_json::json!("pinned-not-published"))
                                })
                        })
                        .unwrap_or(serde_json::json!("unknown"));

                    let mut obj = serde_json::json!({
                        "alias": dep.alias,
                        "state": state_val,
                        "required_here": required_here,
                    });
                    if let Some(p) = &dep.purpose {
                        obj["purpose"] = serde_json::json!(p);
                    }
                    obj
                })
                .collect();

            let overall = compute_overall_from_deps(
                &manifest.asset_deps,
                &alias_to_asset,
                &events,
                &host_ctx,
                &components,
            );

            serde_json::json!({
                "app": manifest.name,
                "deps": deps,
                "overall": overall,
            })
        })
        .collect();

    serde_json::json!({
        "workspace": workspace_root.display().to_string(),
        "services": services_arr,
        "apps": apps_arr,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn empty_report(workspace_root: &Path) -> serde_json::Value {
    serde_json::json!({
        "workspace": workspace_root.display().to_string(),
        "services": [],
        "apps": [],
    })
}

fn replay_last_events(path: &Path) -> HashMap<String, AssetStatusEvent> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(_) => return HashMap::new(),
    };
    let mut map = HashMap::new();
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<AssetStatusEvent>(t) {
            map.insert(ev.asset.clone(), ev);
        }
    }
    map
}

fn infer_state(entry: &workload_spec::AssetEntry) -> AssetState {
    if is_zero_hex(&entry.blake3.0) {
        return AssetState::PlaceholderOutput;
    }
    if let Some(derive) = &entry.derive {
        if is_zero_hex(&derive.fetch.blake3.0) {
            return AssetState::PlaceholderFetch;
        }
    }
    AssetState::PinnedNotPublished
}

fn is_zero_hex(hex: &str) -> bool {
    hex.len() == 64 && hex.bytes().all(|b| b == b'0')
}

fn compute_overall_from_deps(
    deps: &[crate::app_manifest::AssetDep],
    alias_to_asset: &HashMap<String, (String, String)>,
    events: &HashMap<String, AssetStatusEvent>,
    host_ctx: &HostContext,
    components: &[(
        String,
        String,
        Vec<workload_spec::AssetEntry>,
        std::collections::BTreeMap<String, String>,
    )],
) -> &'static str {
    let required_states: Vec<Option<AssetState>> = deps
        .iter()
        .filter(|d| d.required_here(host_ctx))
        .map(|d| {
            alias_to_asset.get(&d.alias).map(|(svc, filename)| {
                let key = format!("{svc}:{filename}");
                events.get(&key).map(|ev| ev.to).unwrap_or_else(|| {
                    components
                        .iter()
                        .find(|(s, _, assets, _)| {
                            s == svc && assets.iter().any(|a| &a.filename == filename)
                        })
                        .and_then(|(_, _, assets, _)| {
                            assets.iter().find(|a| &a.filename == filename)
                        })
                        .map(infer_state)
                        .unwrap_or(AssetState::PinnedNotPublished)
                })
            })
        })
        .collect();

    if required_states.is_empty() {
        return "green";
    }
    for s in &required_states {
        if matches!(
            s,
            Some(AssetState::DriftBucket)
                | Some(AssetState::DriftUpstream)
                | Some(AssetState::TransformBroken)
        ) {
            return "red";
        }
    }
    for s in &required_states {
        if !matches!(
            s,
            Some(AssetState::Published) | Some(AssetState::NotRequired)
        ) {
            return "amber";
        }
    }
    "green"
}
