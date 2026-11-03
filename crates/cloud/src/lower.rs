//! Lower a service component + one mirror into the fleet [`WorkloadSpec`]
//! (W361, R959-F1).
//!
//! A fleet workload is `lower(service, component, mirror)`: a pure, in-memory
//! function of two TOML fragments plus two derived facts.
//!
//! - **Base** — [`WorkloadBase`], `[components.workload]` under the component's
//!   `[[components]]` entry in `service.toml`: the env-invariant part.
//! - **Overlay** — [`WorkloadOverlay`], `[workload.<component-id>]` in
//!   `mirrors/<env>.toml`: what differs per environment, plus `ident`.
//!
//! Merge (W361 §Where the body lives): tables merge key by key and overlay
//! scalars replace base scalars; `env` merges by `name`, `secrets` by target
//! (file path or env-var name), `volumes` by `target` — base order kept, a
//! matching overlay entry replaces in place, overlay-only entries append in
//! overlay order; `depends_on` / `requires` / `capabilities` union; every other
//! array (`command`, `expose.mesh.ports`, …) and `healthcheck.probe` (an enum)
//! is replaced whole. `durability` and `db` are overlay-only.
//!
//! Derived, never authored (refused in either fragment): `name` and
//! `expose.mesh.identity` (overlay `ident`, default
//! [`component_workload_ident`]), and `expose.public.hostname`/`port` (the
//! fronted compute slot's `zone`/`port` — the fields `plan_ingress` reads).
//! Health path, mesh ports, tls and placement annotations are relocated into
//! the fragments verbatim, not derived.
//!
//! A component lowers on a mirror **iff** that mirror declares its overlay.
//!
//! @arch:see(.yah/docs/working/W361-service-lowers-to-workload-spec.md)

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use workload_spec::{validate, WorkloadSpec};

use std::collections::HashMap;

use crate::config::{
    DeployTier, MachineConfig, MirrorConfig, MirrorProviderSlot, ServiceConfig, WorkloadConfig,
};
use crate::inner_door::component_workload_ident;

/// `[components.workload]` — the env-invariant part of a component's
/// `WorkloadSpec`, as a partial spec. Validated when lowered (keys refused
/// under this fragment's own file name), not at parse.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct WorkloadBase(
    #[cfg_attr(
        feature = "json-schema",
        schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")
    )]
    pub toml::Table,
);

/// `[workload.<component-id>]` — the per-environment part of a component's
/// `WorkloadSpec`, plus the optional `ident` (workload name / mesh identity).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct WorkloadOverlay(
    #[cfg_attr(
        feature = "json-schema",
        schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")
    )]
    pub toml::Table,
);

/// The overlay-only key naming the lowered workload.
const IDENT_KEY: &str = "ident";

/// Keys lowering derives; neither fragment may author them.
const DERIVED: &[&str] = &[
    "name",
    "expose.mesh.identity",
    "expose.public.hostname",
    "expose.public.port",
];

/// Keys only an overlay may carry (W361: per-environment by definition).
const OVERLAY_ONLY: &[&str] = &[IDENT_KEY, "durability", "db"];

/// Arrays merged by key; the fn returns an entry's key.
fn keyed(path: &str) -> Option<fn(&toml::Value) -> Option<String>> {
    match path {
        "env" => Some(|v| v.get("name")?.as_str().map(str::to_owned)),
        "volumes" => Some(|v| v.get("target")?.as_str().map(str::to_owned)),
        "secrets" => Some(|v| {
            let t = v.get("target")?;
            if let Some(p) = t.get("file").and_then(|f| f.get("path")).and_then(|p| p.as_str()) {
                return Some(format!("file:{p}"));
            }
            let n = t.get("env_var")?.get("name")?.as_str()?;
            Some(format!("env_var:{n}"))
        }),
        _ => None,
    }
}

/// Arrays whose overlay entries add to the base's.
const UNION: &[&str] = &["depends_on", "requires", "capabilities"];

/// Tables replaced whole rather than merged key by key (enum-shaped).
const REPLACE_WHOLE: &[&str] = &["healthcheck.probe"];

/// Lower `component_id` of `service` on the mirror `mirror_env`.
///
/// `Ok(None)` when the mirror declares no `[workload.<component_id>]`: the
/// component does not run as a fleet workload there.
pub fn lower(
    service: &ServiceConfig,
    component_id: &str,
    mirror_env: &str,
    mirror: &MirrorConfig,
) -> Result<Option<WorkloadSpec>> {
    let Some(overlay) = mirror.workload.get(component_id) else {
        return Ok(None);
    };
    let svc = &service.name;
    let component = service
        .components
        .iter()
        .find(|c| c.id == component_id)
        .with_context(|| {
            format!(
                ".yah/services/{svc}/mirrors/{mirror_env}.toml declares [workload.{component_id}] \
                 but service `{svc}` has no component `{component_id}`"
            )
        })?;
    let base_file =
        format!(".yah/services/{svc}/service.toml [components.workload] of `{component_id}`");
    let overlay_file = format!(".yah/services/{svc}/mirrors/{mirror_env}.toml [workload.{component_id}]");

    let empty = toml::Table::new();
    let base = component.workload.as_ref().map_or(&empty, |b| &b.0);
    for key in DERIVED.iter().chain(OVERLAY_ONLY) {
        if lookup(base, key).is_some() {
            bail!("{base_file} declares `{key}`, which {}", why_refused(key));
        }
    }
    for key in DERIVED {
        if lookup(&overlay.0, key).is_some() {
            bail!("{overlay_file} declares `{key}`, which {}", why_refused(key));
        }
    }
    // W361 decision 4: the lowered spec owns placement, so the compute slot
    // fronting it may not restate one. A second statement is the two-engine
    // shape R959 removes: the slot's said one node, admission another.
    if let Some((role, slot)) = compute_slot(mirror, component_id) {
        for key in PLACEMENT_FIELDS {
            if slot.fields().contains_key(*key) {
                bail!(
                    ".yah/services/{svc}/mirrors/{mirror_env}.toml [providers.{role}] declares \
                     `{key}`, but `{component_id}` lowers on this mirror, so its placement is the \
                     lowered spec's: admission reads `yah.node-selector.mesh-tags`, \
                     `yah.node-selector.node` and `yah.float` from [workload.{component_id}.\
                     annotations], and ingress fronts the nodes it admits (W361 decision 4). \
                     Delete `{key}` from the slot."
                );
            }
        }
    }

    let mut overlay = overlay.0.clone();
    let ident = match overlay.remove(IDENT_KEY) {
        None => component_workload_ident(svc, component_id),
        Some(v) => {
            if component.deploy == DeployTier::Workload {
                bail!(
                    "{overlay_file} declares `ident`, but `{component_id}` is a `deploy = \
                     \"workload\"` component: the inner door routes its mount to `{}`, and an \
                     override would route it to an ident nothing registers",
                    component_workload_ident(svc, component_id)
                );
            }
            v.as_str()
                .with_context(|| format!("{overlay_file}: `ident` must be a string"))?
                .to_owned()
        }
    };

    let mut merged = base.clone();
    merge_table(&mut merged, &overlay, "")?;
    merged.insert("name".into(), ident.clone().into());
    set_path(&mut merged, &["expose", "mesh", "identity"], ident.clone().into());
    match fronted_public(mirror, component_id)? {
        Some((hostname, port)) => {
            set_path(&mut merged, &["expose", "public", "hostname"], hostname.into());
            set_path(&mut merged, &["expose", "public", "port"], i64::from(port).into());
        }
        None => {
            if lookup(&merged, "expose.public").is_some() {
                bail!(
                    "workload `{ident}` declares `expose.public` but mirror `{mirror_env}` fronts \
                     no compute slot for it — the public hostname/port are derived from a fronted \
                     [providers.compute] slot (`zone` + `port`) under an `[[ingress]]` edge"
                );
            }
        }
    }

    let label = format!("lowered workload `{ident}` ({base_file} + {overlay_file})");
    let src = toml::to_string(&merged).with_context(|| format!("serialising {label}"))?;
    let spec: WorkloadSpec = toml::from_str(&src).with_context(|| format!("parsing {label}"))?;
    crate::config::refuse_dropped_keys(&src, &spec, &label)?;
    let kept = toml::Value::try_from(&spec).with_context(|| format!("re-serialising {label}"))?;
    refuse_fragment_dropped_keys(base, &kept, &base_file)?;
    refuse_fragment_dropped_keys(&overlay, &kept, &overlay_file)?;
    // Also refuses a fronted port missing from `expose.mesh.ports` (W361).
    validate::shape(&spec).map_err(|e| anyhow::anyhow!("{label} failed shape validation: {e}"))?;
    Ok(Some(spec))
}

/// W361 §Migration's equality as a normal form: `env` (by name), `secrets`
/// (by target) and `volumes` (by target) sorted so they compare as keyed
/// sets; everything else is left to compare exactly. Two specs are equal
/// under that equality iff their normal forms are `==`.
pub fn keyed_sets(mut spec: WorkloadSpec) -> WorkloadSpec {
    spec.env.sort_by(|a, b| a.name.cmp(&b.name));
    spec.secrets.sort_by_key(|s| format!("{:?}", s.target));
    spec.volumes.sort_by(|a, b| a.target.cmp(&b.target));
    spec
}

fn why_refused(key: &str) -> &'static str {
    match key {
        "name" | "expose.mesh.identity" => "is derived from the overlay's `ident`",
        "expose.public.hostname" | "expose.public.port" => {
            "is derived from the mirror's fronted [providers.compute] `zone`/`port`"
        }
        _ => "is per-environment and belongs in the mirror's [workload.<component>] overlay",
    }
}

/// Compute-slot fields that state a placement; refused on a lowered
/// component's slot (W361 decision 4).
const PLACEMENT_FIELDS: &[&str] = &["machine", "machines", "required"];

/// The mirror's compute slot for `component_id`: `compute:<id>` first, then
/// `compute`.
fn compute_slot<'m>(
    mirror: &'m MirrorConfig,
    component_id: &str,
) -> Option<(&'m String, &'m MirrorProviderSlot)> {
    let role = format!("compute:{component_id}");
    mirror
        .providers
        .get_key_value(role.as_str())
        .or_else(|| mirror.providers.get_key_value("compute"))
}

/// A compute slot placed by admission rather than by its own fields (R959-F6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedSlot {
    /// Every machine admission accepts the lowered spec on, in declaration
    /// order: the nodes that *could* hold it.
    pub machines: Vec<String>,
    /// The spec's `replicas`: how many of `machines` hold it at once. A
    /// verifier needs it because the rest answering "no record" is expected,
    /// not a missing replica.
    pub replicas: u32,
}

/// Ingress placement for each compute slot whose component lowers on `mirror`
/// (W361 decision 4, R959-F6), keyed by slot role.
///
/// This is what `resolve_ingress_placements` takes for those slots in place of
/// a slot-declared `machine`/`required`, which [`lower`] refuses. It is the
/// admissible *set*, not the one node holding the workload today, for the
/// reason `resolve_ingress_candidates` widens a bundle slot's poll list: the
/// rule follows a move placement hasn't made yet, and live discovery still
/// decides which of them answers (R844).
///
/// A mirror with no ingress edge yields an empty map without lowering
/// anything, since only ingress planning reads it. An empty admissible set is
/// an error naming the workload, never a silently unplaced rule.
pub fn admitted_compute_slots(
    service: &ServiceConfig,
    mirror_env: &str,
    mirror: &MirrorConfig,
    machines: &[MachineConfig],
    declared: &[WorkloadConfig],
) -> Result<HashMap<String, AdmittedSlot>> {
    if mirror.ingress.is_absent() {
        return Ok(HashMap::new());
    }
    let mut by_role: HashMap<String, (String, AdmittedSlot)> = HashMap::new();
    for component in &service.components {
        let Some((role, _)) = compute_slot(mirror, &component.id) else {
            continue;
        };
        let Some(spec) = lower(service, &component.id, mirror_env, mirror)? else {
            continue;
        };
        let admissible: Vec<String> = crate::config::admissible_machines(machines, &spec, declared)
            .with_context(|| {
                format!(
                    "placing workload `{}` behind [providers.{role}] of .yah/services/{}/mirrors/\
                     {mirror_env}.toml",
                    spec.name, service.name
                )
            })?
            .into_iter()
            .map(|m| m.name.clone())
            .collect();
        let slot = AdmittedSlot {
            machines: admissible,
            replicas: spec.replicas,
        };
        if let Some((other, _)) = by_role.insert(role.clone(), (component.id.clone(), slot)) {
            bail!(
                ".yah/services/{}/mirrors/{mirror_env}.toml: [providers.{role}] fronts two \
                 lowered components, `{other}` and `{}`. Give each its own \
                 [providers.compute:<component>] slot.",
                service.name,
                component.id
            );
        }
    }
    Ok(by_role.into_iter().map(|(role, (_, slot))| (role, slot)).collect())
}

/// The mirror's compute slot for `component_id` (see [`compute_slot`]) as
/// `(zone, port)`, iff it is fronted (`port` or `fronted = true`, exactly
/// `plan_ingress`'s opt-in) and the mirror declares an ingress edge.
fn fronted_public(mirror: &MirrorConfig, component_id: &str) -> Result<Option<(String, u16)>> {
    if mirror.ingress.is_absent() {
        return Ok(None);
    }
    let Some((role, slot)) = compute_slot(mirror, component_id) else {
        return Ok(None);
    };
    let fields = slot.fields();
    let port = fields.get("port").and_then(|v| v.as_integer());
    let fronted = fields.get("fronted").and_then(|v| v.as_bool()).unwrap_or(false);
    if port.is_none() && !fronted {
        return Ok(None);
    }
    let zone = fields
        .get("zone")
        .and_then(|v| v.as_str())
        .with_context(|| format!("[providers.{role}] is fronted but declares no `zone`"))?;
    let port = port.with_context(|| {
        format!(
            "[providers.{role}] is fronted with no `port`; a lowered workload's \
             `expose.public.port` is derived from it, so declare `port`"
        )
    })?;
    let port = u16::try_from(port)
        .with_context(|| format!("[providers.{role}] port = {port} is not a valid TCP port"))?;
    Ok(Some((zone.to_owned(), port)))
}

fn lookup<'a>(table: &'a toml::Table, dotted: &str) -> Option<&'a toml::Value> {
    let mut parts = dotted.split('.');
    let mut cur = table.get(parts.next()?)?;
    for p in parts {
        cur = cur.as_table()?.get(p)?;
    }
    Some(cur)
}

fn set_path(table: &mut toml::Table, path: &[&str], value: toml::Value) {
    let (last, parents) = path.split_last().expect("non-empty path");
    let mut cur = table;
    for p in parents {
        let entry = cur
            .entry(p.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !entry.is_table() {
            *entry = toml::Value::Table(toml::Table::new());
        }
        cur = entry.as_table_mut().expect("just ensured a table");
    }
    cur.insert(last.to_string(), value);
}

fn merge_table(dst: &mut toml::Table, src: &toml::Table, prefix: &str) -> Result<()> {
    for (key, value) in src {
        let path = format!("{prefix}{key}");
        match (dst.get_mut(key), value) {
            (Some(toml::Value::Table(d)), toml::Value::Table(s))
                if !REPLACE_WHOLE.contains(&path.as_str()) =>
            {
                merge_table(d, s, &format!("{path}."))?;
            }
            (Some(toml::Value::Array(d)), toml::Value::Array(s)) => {
                if let Some(key_of) = keyed(&path) {
                    for item in s {
                        let k = key_of(item)
                            .with_context(|| format!("`{path}` entry has no key: {item}"))?;
                        match d.iter().position(|e| key_of(e).as_deref() == Some(k.as_str())) {
                            Some(i) => d[i] = item.clone(),
                            None => d.push(item.clone()),
                        }
                    }
                } else if UNION.contains(&path.as_str()) {
                    for item in s {
                        if !d.contains(item) {
                            d.push(item.clone());
                        }
                    }
                } else {
                    *d = s.clone();
                }
            }
            _ => {
                dst.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

/// The R892-B1 dropped-key check for one fragment: every key the fragment
/// declares must survive into the lowered spec's re-serialisation, so a
/// misspelling is refused under the file that holds it.
fn refuse_fragment_dropped_keys(fragment: &toml::Table, kept: &toml::Value, file: &str) -> Result<()> {
    let mut dropped = Vec::new();
    collect(&toml::Value::Table(fragment.clone()), kept, "", &mut dropped);
    dropped.retain(|p| !workload_spec::RETIRED_KEYS.iter().any(|r| r.path == p));
    if dropped.is_empty() {
        return Ok(());
    }
    bail!(
        "{file} declares {} the workload schema does not have, and their values would be \
         discarded in silence:\n  {}\n\nDelete them, or correct the spelling (R892).",
        if dropped.len() == 1 { "a key" } else { "keys" },
        dropped.join("\n  ")
    );

    fn collect(declared: &toml::Value, kept: &toml::Value, prefix: &str, out: &mut Vec<String>) {
        match (declared, kept) {
            (toml::Value::Table(d), toml::Value::Table(k)) => {
                for (key, value) in d {
                    let path = format!("{prefix}{key}");
                    match k.get(key) {
                        Some(kv) => match (keyed(&path), value, kv) {
                            (Some(key_of), toml::Value::Array(da), toml::Value::Array(ka)) => {
                                for item in da {
                                    let Some(name) = key_of(item) else { continue };
                                    if let Some(ki) =
                                        ka.iter().find(|e| key_of(e).as_deref() == Some(name.as_str()))
                                    {
                                        collect(item, ki, &format!("{path}[{name}]."), out);
                                    }
                                }
                            }
                            _ => collect(value, kv, &format!("{path}."), out),
                        },
                        None => out.push(path),
                    }
                }
            }
            (toml::Value::Array(d), toml::Value::Array(k)) if d.len() == k.len() => {
                for (i, (dv, kv)) in d.iter().zip(k).enumerate() {
                    collect(dv, kv, &format!("{prefix}{i}."), out);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lower");

    fn read(rel: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{rel}")).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn service(rel: &str) -> ServiceConfig {
        toml::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn mirror(rel: &str) -> MirrorConfig {
        toml::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn assert_lowers_to(svc: &str, component: &str, env: &str, live: &str) {
        let lowered = lower(&service(&format!("{svc}/service.toml")), component, env, &mirror(&format!("{svc}/{env}.toml")))
            .unwrap()
            .expect("mirror declares the overlay");
        let live: WorkloadSpec = toml::from_str(&read(live)).unwrap();
        assert_eq!(keyed_sets(lowered), keyed_sets(live));
    }

    #[test]
    fn yah_cloud_admin_prod_lowers_to_the_live_spec() {
        assert_lowers_to("yah-cloud-admin", "cloud-admin", "prod", "live/yah-cloud-admin.toml");
    }

    #[test]
    fn noisetable_account_prod_lowers_to_the_live_spec() {
        assert_lowers_to("noisetable-api", "api", "prod", "live/noisetable-account.toml");
    }

    #[test]
    fn noisetable_account_staging_lowers_to_the_live_spec() {
        assert_lowers_to("noisetable-api", "api", "staging", "live/noisetable-account-staging.toml");
    }

    #[test]
    fn noisetable_marketing_issues_prod_lowers_to_the_live_spec() {
        assert_lowers_to("noisetable-marketing", "issues", "prod", "live/noisetable-marketing-issues.toml");
    }

    /// R959-T3: each dev-rig mirror (one per microVM guest) lowers to its
    /// on-disk `.yah/infra/workloads/vm-us-west-NNN.toml`.
    #[test]
    fn every_dev_rig_guest_lowers_to_its_live_spec() {
        for n in ["111", "112", "113", "141", "142", "143"] {
            let env = format!("vm-us-west-{n}");
            assert_lowers_to("dev-rig", "guest", &env, &format!("live/{env}.toml"));
        }
    }

    /// R959-T4: every noisetable workload TOML has a lowering that matches.
    #[test]
    fn every_noisetable_appliance_lowers_to_its_live_spec() {
        for (svc, component, env, live) in [
            ("noisetable-compiler", "compiler", "prod", "noisetable-compiler"),
            ("noisetable-compiler", "compiler", "staging", "noisetable-compiler-staging"),
            ("noisetable-coordinator", "coordinator", "prod", "noisetable-coordinator"),
            ("noisetable-coordinator", "coordinator", "staging", "noisetable-coordinator-staging"),
            ("noisetable-seed", "seed", "prod", "noisetable-seed"),
            ("noisetable-seed", "seed", "staging", "noisetable-seed-staging"),
            ("noisetable-relay", "relay", "prod", "noisetable-relay"),
        ] {
            assert_lowers_to(svc, component, env, &format!("live/{live}.toml"));
        }
    }

    #[test]
    fn a_mirror_without_the_overlay_does_not_lower() {
        let mut m = mirror("noisetable-api/prod.toml");
        m.workload.clear();
        assert!(lower(&service("noisetable-api/service.toml"), "api", "prod", &m).unwrap().is_none());
    }

    #[test]
    fn overlay_entries_replace_in_place_and_append_in_order() {
        let mut base = toml::Table::new();
        base.insert(
            "env".into(),
            toml::Value::try_from(vec![
                toml::toml! { name = "A" value = 1 },
                toml::toml! { name = "B" value = 1 },
            ])
            .unwrap(),
        );
        let overlay: toml::Table = toml::toml! {
            [[env]]
            name = "C"
            value = 2
            [[env]]
            name = "A"
            value = 2
        };
        merge_table(&mut base, &overlay, "").unwrap();
        let names: Vec<_> = base["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["name"].as_str().unwrap().to_owned(), e["value"].as_integer().unwrap()))
            .collect();
        assert_eq!(names, [("A".into(), 2), ("B".into(), 1), ("C".into(), 2)]);
    }

    #[test]
    fn a_misspelled_base_key_is_refused_under_the_service_file() {
        let mut svc = service("noisetable-api/service.toml");
        svc.components[0].workload.as_mut().unwrap().0.insert("restart_polcy".into(), "always".into());
        let err = lower(&svc, "api", "prod", &mirror("noisetable-api/prod.toml")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("restart_polcy"), "{msg}");
    }

    #[test]
    fn a_misspelled_overlay_key_is_refused_under_the_mirror_file() {
        let mut m = mirror("noisetable-api/prod.toml");
        m.workload.get_mut("api").unwrap().0.insert("annotatons".into(), toml::Value::Table(Default::default()));
        let msg = format!("{:#}", lower(&service("noisetable-api/service.toml"), "api", "prod", &m).unwrap_err());
        assert!(msg.contains("annotatons"), "{msg}");
    }

    #[test]
    fn derived_and_overlay_only_keys_are_refused_in_the_base() {
        for key in ["name", "durability", "ident"] {
            let mut svc = service("noisetable-api/service.toml");
            svc.components[0].workload.as_mut().unwrap().0.insert(key.into(), "x".into());
            let msg = format!("{:#}", lower(&svc, "api", "prod", &mirror("noisetable-api/prod.toml")).unwrap_err());
            assert!(msg.contains("service.toml") && msg.contains(key), "{msg}");
        }
    }

    #[test]
    fn a_deploy_workload_component_may_not_override_its_ident() {
        let mut m = mirror("noisetable-marketing/prod.toml");
        m.workload.get_mut("issues").unwrap().0.insert("ident".into(), "other".into());
        let msg = format!("{:#}", lower(&service("noisetable-marketing/service.toml"), "issues", "prod", &m).unwrap_err());
        assert!(msg.contains("inner door"), "{msg}");
    }

    #[test]
    fn a_fronted_port_the_workload_does_not_expose_is_refused() {
        let mut m = mirror("noisetable-api/staging.toml");
        let ports = toml::Value::try_from(vec![9999]).unwrap();
        set_path(&mut m.workload.get_mut("api").unwrap().0, &["expose", "mesh", "ports"], ports);
        let msg = format!("{:#}", lower(&service("noisetable-api/service.toml"), "api", "staging", &m).unwrap_err());
        assert!(msg.contains("port 4332 must appear in expose.mesh.ports"), "{msg}");
    }

    #[test]
    fn public_expose_without_a_fronted_slot_is_refused() {
        let mut m = mirror("noisetable-api/prod.toml");
        m.providers.clear();
        let msg = format!("{:#}", lower(&service("noisetable-api/service.toml"), "api", "prod", &m).unwrap_err());
        assert!(msg.contains("fronts no compute slot"), "{msg}");
    }

    // ─── R959-F6: the lowered spec owns placement ───────────────────────────

    #[test]
    fn a_compute_slot_may_not_restate_a_lowered_components_placement() {
        let svc = service("noisetable-api/service.toml");
        for line in [
            "machine = \"us-east-001\"",
            "machines = [\"us-east-001\"]",
            "required = { regions = [\"us-east\"] }",
        ] {
            let src = read("noisetable-api/prod.toml")
                .replacen("kind = \"static\"\n", &format!("kind = \"static\"\n{line}\n"), 1);
            let m: MirrorConfig = toml::from_str(&src).unwrap();
            let key = line.split(' ').next().unwrap();
            let msg = format!("{:#}", lower(&svc, "api", "prod", &m).unwrap_err());
            assert!(
                msg.contains(&format!("[providers.compute] declares `{key}`"))
                    && msg.contains("W361 decision 4"),
                "{msg}"
            );
            // Scoped to a component that lowers: the same slot is left alone
            // on a mirror that does not lower `api`.
            let mut unlowered = m.clone();
            unlowered.workload.clear();
            assert!(lower(&svc, "api", "prod", &unlowered).unwrap().is_none());
        }
    }

    /// R1019-F28 (W388): name `role` on the `api` overlay's node selector.
    /// The noisetable fixtures are W361 migration records that predate roles,
    /// and placement is now fail-closed on them, so the placement tests add
    /// the role here rather than rewriting the records.
    fn naming_role(mut m: MirrorConfig, role: &str) -> MirrorConfig {
        let overlay = &mut m.workload.get_mut("api").expect("api overlay").0;
        let annotations = overlay
            .entry("annotations")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("annotations is a table");
        let key = workload_spec::NODE_SELECTOR_MESH_TAGS_ANNOTATION;
        let joined = match annotations.get(key).and_then(|v| v.as_str()) {
            Some(sel) if !sel.is_empty() => format!("{sel},{role}"),
            _ => role.to_string(),
        };
        annotations.insert(key.into(), joined.into());
        m
    }

    fn machine(name: &str, extra: &str) -> MachineConfig {
        toml::from_str(&format!(
            "name = \"{name}\"\nprovider = \"static\"\nhosts_mirrors = []\nssh_keys = []\n{extra}"
        ))
        .expect("machine config parses")
    }

    /// The fleet shape noisetable-api is placed against: three prod raft
    /// members, one of which repels appliances, then two dev-raft Pis.
    fn fleet() -> Vec<MachineConfig> {
        let prod = "mesh_tags = [\"arch:x86\", \"os:linux\", \"role:public-uptime\"]\n\
                    sovereign_group = \"prod\"\nsovereign_participation = \"in\"\n";
        let dev = "mesh_tags = [\"arch:arm\", \"os:linux\", \"role:dev-cluster\"]\n\
                   sovereign_group = \"dev\"\nsovereign_participation = \"in\"\n";
        vec![
            machine("us-east-001", prod),
            machine("us-south-001", &format!("{prod}taints = [\"no-appliance\"]\n")),
            machine("us-west-001", prod),
            machine("us-west-011", dev),
            machine("us-west-013", dev),
        ]
    }

    #[test]
    fn a_lowered_fronted_slot_is_placed_on_every_node_admission_accepts() {
        let svc = service("noisetable-api/service.toml");
        // prod floats (`yah.float = "cluster"`): the prod raft members that
        // tolerate an appliance. Never the dev raft, although every dev Pi
        // admits an unconstrained spec.
        let prod_mirror = naming_role(mirror("noisetable-api/prod.toml"), workload_spec::PUBLIC_UPTIME_ROLE);
        let prod = admitted_compute_slots(&svc, "prod", &prod_mirror, &fleet(), &[]).unwrap();
        assert_eq!(prod.len(), 1, "{prod:?}");
        assert_eq!(prod["compute"].machines, ["us-east-001", "us-west-001"]);
        assert_eq!(prod["compute"].replicas, 1);
        // staging selects `arch:arm,os:linux`: every node matching it, not
        // just the us-west-011 the slot used to name.
        let staging_mirror =
            naming_role(mirror("noisetable-api/staging.toml"), workload_spec::DEV_CLUSTER_ROLE);
        let staging = admitted_compute_slots(&svc, "staging", &staging_mirror, &fleet(), &[]).unwrap();
        assert_eq!(staging["compute"].machines, ["us-west-011", "us-west-013"]);
    }

    #[test]
    fn a_mirror_without_an_ingress_edge_places_nothing() {
        let admitted = admitted_compute_slots(
            &service("yah-cloud-admin/service.toml"),
            "prod",
            &mirror("yah-cloud-admin/prod.toml"),
            &fleet(),
            &[],
        )
        .unwrap();
        assert!(admitted.is_empty(), "{admitted:?}");
    }

    #[test]
    fn an_empty_admissible_set_is_an_error_naming_the_workload() {
        let standalone: Vec<MachineConfig> = fleet()
            .into_iter()
            .map(|mut m| {
                m.sovereign_group = None;
                m
            })
            .collect();
        let msg = format!(
            "{:#}",
            admitted_compute_slots(
                &service("noisetable-api/service.toml"),
                "prod",
                &naming_role(mirror("noisetable-api/prod.toml"), workload_spec::PUBLIC_UPTIME_ROLE),
                &standalone,
                &[],
            )
            .unwrap_err()
        );
        assert!(msg.contains("noisetable-account") && msg.contains("raft member"), "{msg}");
    }
}

/// Test-only camp builder: declare a workload the only way a camp can now,
/// as a `.yah/services/<name>/` service plus `mirrors/prod.toml` overlay
/// (R959-T5 deleted the `.yah/infra/workloads/` reader).
#[cfg(test)]
pub(crate) mod fixture {
    use std::path::Path;

    /// Write `spec_toml` (a whole `WorkloadSpec` document) as service `name`:
    /// `name` and `expose.mesh.identity` are derived, `durability`/`db` are
    /// overlay-only, and everything else is the env-invariant base.
    pub(crate) fn write_workload(root: &Path, name: &str, spec_toml: &str) {
        let mut spec: toml::Table = toml::from_str(spec_toml).unwrap();
        spec.remove("name");
        // R1019-F28 (W388): placement is fail-closed on node roles, so a
        // fixture workload that names no selector names the role fixture
        // machines serve (`role:public-uptime`), as every real spec must.
        let annotations = spec
            .entry("annotations")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("annotations is a table");
        annotations
            .entry(workload_spec::NODE_SELECTOR_MESH_TAGS_ANNOTATION)
            .or_insert_with(|| workload_spec::PUBLIC_UPTIME_ROLE.into());
        if let Some(mesh) = spec
            .get_mut("expose")
            .and_then(|e| e.get_mut("mesh"))
            .and_then(|m| m.as_table_mut())
        {
            mesh.remove("identity");
        }
        // A public hostname is derived from a fronted compute slot under an
        // `[[ingress]]` edge, so it moves out of the spec into the mirror.
        let public = spec
            .get_mut("expose")
            .and_then(|e| e.get_mut("public"))
            .and_then(|p| p.as_table_mut())
            .map(|p| (p.remove("hostname"), p.remove("port")));
        let mut overlay = toml::Table::new();
        overlay.insert("ident".into(), name.into());
        for key in ["durability", "db"] {
            if let Some(v) = spec.remove(key) {
                overlay.insert(key.into(), v);
            }
        }
        let component = toml::toml! {
            id = "main"
            kind = "container"
            path = "."
            role = "compute"
        };
        let mut component = component;
        component.insert("workload".into(), spec.into());
        let mut service = toml::Table::new();
        service.insert("schema_version".into(), 1.into());
        service.insert("name".into(), name.into());
        service.insert(
            "address".into(),
            toml::toml! {
                kind = "front-door"
                domain = "fixture.mesh.yah.dev"
            }
            .into(),
        );
        service.insert("components".into(), vec![toml::Value::Table(component)].into());
        let mut mirror = toml::Table::new();
        mirror.insert("schema_version".into(), 1.into());
        mirror.insert("shape".into(), "single-machine".into());
        if let Some((Some(hostname), Some(port))) = public {
            mirror.insert(
                "ingress".into(),
                vec![toml::Value::Table(toml::toml! {
                    provider = "passway"
                    machines = ["a"]
                })]
                .into(),
            );
            let mut compute = toml::Table::new();
            compute.insert("kind".into(), "static".into());
            compute.insert("zone".into(), hostname);
            compute.insert("port".into(), port);
            mirror.insert(
                "providers".into(),
                toml::Table::from_iter([("compute".to_string(), compute.into())]).into(),
            );
        }
        let mut workload = toml::Table::new();
        workload.insert("main".into(), overlay.into());
        mirror.insert("workload".into(), workload.into());

        let dir = crate::paths::services_dir(root).join(name);
        std::fs::create_dir_all(dir.join("mirrors")).unwrap();
        std::fs::write(dir.join("service.toml"), toml::to_string(&service).unwrap()).unwrap();
        std::fs::write(dir.join("mirrors/prod.toml"), toml::to_string(&mirror).unwrap()).unwrap();
    }
}
