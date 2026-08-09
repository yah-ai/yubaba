//! Public-ingress provider seam — `mirror.ingress` → live front-door state.
//!
//! Part of R594-F11 (W267 §"Ingress is a provider, not a fixed part of the
//! stack"). The canonical ticket annotation lives in
//! `.yah/docs/working/W267-sovereign-public-ingress.md`.
//!
//! A mirror declares **one** front door
//! ([`IngressProvider`](crate::config::IngressProvider)) and the rules it
//! needs published are derived, not typed in:
//!
//! ```text
//! slots with `zone` + `port`  →  IngressPlan { provider, rules }
//!                                           ├── cloudflare-tunnel → CF API ingress config
//!                                           └── passway           → PASSWAY_UPSTREAMS
//! ```
//!
//! [`plan_ingress`] is pure and provider-agnostic on purpose: the same
//! `(hostname, port)` pairs feed either arm, so flipping
//! `ingress = "cloudflare-tunnel"` to `ingress = "passway"` needs no other edit
//! to the mirror. That is the whole point of calling ingress a *provider* —
//! walking W267's tier ladder is a config flip, not a rewrite.
//!
//! **The provider owns addressing, never rendering.** A rule carries a
//! hostname and a local port — enough to *dial*, and deliberately nothing about
//! what any path means. The W173 render cube stays in mesofact's manifest
//! (W267 §"Two front doors, one render contract"); growing a path-based router
//! here would mint a third copy of those rules.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tracing::{debug, info};

use crate::config::IngressProvider;
use crate::{CloudflareClient, MirrorConfig};

/// Slot field naming the public hostname a slot is fronted at.
const ZONE_FIELD: &str = "zone";
/// Slot field that opts a slot into the front door: the node-local port its
/// workload listens on. Already `BundleSlot.port`'s meaning — the port kamaji
/// binds the workload to and the port the front door dials are the same port,
/// so this reuses that field rather than minting a parallel one.
///
/// `port` is the opt-in and `zone` is not, because `zone` is overloaded: a
/// CDN-published static slot carries it meaning the *Cloudflare zone*. Keying
/// participation off `zone` would drag every such slot into the ingress plan
/// and fail the apply of mirrors that have no front door at all.
const PORT_FIELD: &str = "port";
/// Slot field naming the machine the fronted workload runs on.
const MACHINE_FIELD: &str = "machine";
/// Slot field pinning the address the front door dials, overriding discovery.
const UPSTREAM_HOST_FIELD: &str = "upstream_host";

/// One hostname→local-port rule the front door must publish.
///
/// Provider-agnostic by construction: [`service_url`](Self::service_url)
/// renders it for cloudflared, [`passway_upstream`](Self::passway_upstream)
/// for passway's `PASSWAY_UPSTREAMS` grammar (R594-F10 host fan-in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRule {
    /// Public hostname, e.g. `analytics.yah.dev`.
    pub hostname: String,
    /// Node-local port the fronted workload listens on.
    pub port: u16,
    /// Mirror provider slot this rule was derived from (`"compute"`, …). Kept
    /// so an error or a summary line can name the slot the operator wrote.
    pub slot: String,
    /// The slot's `use = "<provider-id>"`, when it references an infra-declared
    /// provider. The cloudflare-tunnel arm resolves its account id + API token
    /// through this, exactly as the R2 custom-domain reconciler does.
    pub provider_id: Option<String>,
    /// The slot's `machine = "<name>"`, when declared. Names the node whose
    /// `MachineConfig.cloudflared` tunnel id the rules get published to.
    pub machine: Option<String>,
    /// Address the front door dials this workload at. `None` until
    /// [`IngressPlan::resolve_upstreams`] runs.
    ///
    /// **Not a defaultable field.** Loopback used to be a safe assumption —
    /// kamaji forked `mesofact-serve --listen 127.0.0.1:<port>` and every front
    /// door was co-located with what it fronted. R599-F12 changed that:
    /// `native_bind_ip` now binds the workload's allocated `MeshAssignment`
    /// mesh IP, so a rule that assumed loopback would dial a port nothing is
    /// listening on — and fail at *request* time, long after the apply that
    /// looked clean. The mesh IP is allocated by yubaba at deploy time and is
    /// therefore unknowable from the mirror, so it has to be resolved, not
    /// guessed.
    pub upstream_host: Option<String>,
}

impl IngressRule {
    /// The `host:port` the front door dials, once resolved.
    pub fn upstream(&self) -> Result<String> {
        let host = self.upstream_host.as_deref().with_context(|| {
            format!(
                "slot [providers.{}] has no resolved upstream address for {}: the workload's \
                 mesh IP is allocated at deploy time (R599-F12), so it cannot come from the \
                 mirror. Either the fronting node's `GET /service-records?ready=true` must \
                 report a ready record exposing port {}, or the slot must pin \
                 `{UPSTREAM_HOST_FIELD} = \"<addr>\"` explicitly.",
                self.slot, self.hostname, self.port
            )
        })?;
        Ok(format!("{host}:{}", self.port))
    }

    /// cloudflared ingress-rule `service` target.
    pub fn service_url(&self) -> Result<String> {
        Ok(format!("http://{}", self.upstream()?))
    }

    /// One `PASSWAY_UPSTREAMS` entry in the R594-F10 host-prefixed form.
    pub fn passway_upstream(&self) -> Result<String> {
        Ok(format!("{}={}", self.hostname, self.upstream()?))
    }
}

/// What a mirror's declared front door has to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressPlan {
    pub provider: IngressProvider,
    /// Derived rules, ordered by hostname so a plan is stable across runs and
    /// two applies produce byte-identical config.
    pub rules: Vec<IngressRule>,
}

impl IngressPlan {
    /// Every rule rendered as a `PASSWAY_UPSTREAMS` entry, ready to hand to
    /// `PasswayIngressSpec::upstreams`.
    pub fn passway_upstreams(&self) -> Result<Vec<String>> {
        self.rules
            .iter()
            .map(IngressRule::passway_upstream)
            .collect()
    }

    /// Fill in the address each rule's front door dials.
    ///
    /// A rule that pinned `upstream_host` on its slot keeps it — an explicit
    /// operator override always wins, and it is the escape hatch for a node
    /// with no mesh plane. Every other rule is handed to `discover`, which the
    /// apply layer backs with the fronting node's
    /// `GET /service-records?ready=true` — the same surface passway's own
    /// `YubabaUpstreams` consumes (R594-F8). That is the seam rule restated:
    /// **an ingress provider derives its config from placement.** A proxy you
    /// hand an address list to is a deployment, not a provider.
    ///
    /// A rule left unresolved is an error here rather than a dead upstream
    /// later. Discovery returning `Ok(None)` for a rule means the control plane
    /// answered and has no ready record on that port — the workload is not up,
    /// so publishing a hostname for it would advertise a 502.
    pub fn resolve_upstreams<F>(&mut self, mut discover: F) -> Result<()>
    where
        F: FnMut(&IngressRule) -> Result<Option<String>>,
    {
        for rule in &mut self.rules {
            if rule.upstream_host.is_some() {
                continue;
            }
            rule.upstream_host = discover(rule)?;
            // Surface the failure with the rule's own context.
            rule.upstream()?;
        }
        Ok(())
    }

    /// Provider id the front door's credentials resolve through — the `use`
    /// of the first fronted slot that names one.
    pub fn provider_id(&self) -> Option<&str> {
        self.rules.iter().find_map(|r| r.provider_id.as_deref())
    }

    /// Machine the front door is placed on — the `machine` of the first fronted
    /// slot that names one.
    pub fn machine(&self) -> Option<&str> {
        self.rules.iter().find_map(|r| r.machine.as_deref())
    }
}

/// The front door this mirror declares, or `None` when it has none.
///
/// The dispatch-layer predicate, mirroring
/// [`mesofact_bundle::slot_declared`](super::mesofact_bundle::slot_declared):
/// checked before any provider-specific work runs, so the two arms stay
/// mutually exclusive per mirror.
pub fn declared(mirror: &MirrorConfig) -> Option<IngressProvider> {
    mirror.ingress.is_declared().then_some(mirror.ingress)
}

/// Derive the front door's rules from the mirror's provider slots.
///
/// A slot participates when it declares `port`; its `zone` is the public
/// hostname that port is fanned in at. `port` without a `zone` is an **error**,
/// not a skip — a mirror that declares a front door and a fronted port but no
/// hostname is always a typo, and silently dropping it is exactly the failure
/// mode where an operator flips `ingress = "cloudflare-tunnel"` and gets a
/// front door that publishes nothing. A slot with `zone` and no `port` is
/// skipped: that is a CDN-published tier, not a fronted one.
///
/// Returns `Ok(None)` when the mirror declares no ingress provider.
pub fn plan_ingress(mirror: &MirrorConfig) -> Result<Option<IngressPlan>> {
    let Some(provider) = declared(mirror) else {
        return Ok(None);
    };

    let mut rules = Vec::new();
    for (role, slot) in &mirror.providers {
        let fields = slot.fields();
        let Some(port) = fields.get(PORT_FIELD).and_then(|v| v.as_integer()) else {
            continue;
        };
        let Some(zone) = fields.get(ZONE_FIELD).and_then(|v| v.as_str()) else {
            bail!(
                "mirror declares ingress = {:?} and slot [providers.{role}] declares \
                 {PORT_FIELD} = {port}, but no `zone` — an ingress provider fans a public \
                 hostname in to a node-local port, so it has nothing to publish that port \
                 at. Add `zone = \"<hostname>\"` to the slot, or drop `{PORT_FIELD}` if \
                 this slot is not fronted.",
                provider.as_str()
            );
        };
        let port = u16::try_from(port).with_context(|| {
            format!("slot [providers.{role}] {PORT_FIELD} = {port} is not a valid TCP port")
        })?;
        rules.push(IngressRule {
            hostname: zone.to_string(),
            port,
            slot: role.clone(),
            provider_id: slot.provider_id().map(str::to_string),
            machine: fields
                .get(MACHINE_FIELD)
                .and_then(|v| v.as_str())
                .map(str::to_string),
            upstream_host: fields
                .get(UPSTREAM_HOST_FIELD)
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }

    // Stable order: two applies of an unchanged mirror must produce identical
    // provider config, or every run looks like drift.
    rules.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    if rules.is_empty() {
        bail!(
            "mirror declares ingress = {:?} but no provider slot declares `{PORT_FIELD}` — \
             there is nothing to publish. Either add `zone` + `{PORT_FIELD}` to the slot \
             the front door fronts, or remove the `ingress` field.",
            provider.as_str()
        );
    }

    Ok(Some(IngressPlan { provider, rules }))
}

// ── cloudflare-tunnel arm ────────────────────────────────────────────────────

/// Ensure the tunnel's remotely-managed ingress config publishes `plan`'s
/// rules.
///
/// Token-form tunnels keep their ingress rules in Cloudflare's API rather than
/// in a file on the box (W267 §Granularity), so this is an API-call job, not a
/// config render.
///
/// **A failed API call is never read as "delete every hostname rule."** The
/// GET's error propagates and no PUT is attempted — the same rule the
/// sovereign arm follows for a failed `GET /service-records` (W267 §"The seam,
/// settled", constraint 2). Rules for hostnames this mirror does not own are
/// preserved verbatim, because one tunnel multiplexes every service on the
/// node.
///
/// Idempotent: when the merged config equals the live one, no PUT is made.
///
/// Required token scope: `Cloudflare Tunnel: Edit`.
pub async fn ensure_tunnel_ingress(
    cf: &CloudflareClient,
    account_id: &str,
    tunnel_id: &str,
    plan: &IngressPlan,
) -> Result<TunnelIngressOutcome> {
    let live = cf
        .tunnel_configuration(account_id, tunnel_id)
        .await
        .with_context(|| format!("reading ingress configuration of tunnel {tunnel_id}"))?;

    let live_ingress = live
        .get("ingress")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let merged = merge_tunnel_ingress(&live_ingress, &plan.rules)?;
    if merged == live_ingress {
        debug!(tunnel_id, "tunnel ingress already current — skipping PUT");
        return Ok(TunnelIngressOutcome::AlreadyCurrent);
    }

    // Preserve every sibling key of the config object (warp-routing,
    // originRequest defaults, …) — we own `ingress` and nothing else.
    let mut config = live;
    config
        .as_object_mut()
        .expect("tunnel_configuration always yields a JSON object")
        .insert("ingress".into(), Value::Array(merged));

    cf.put_tunnel_configuration(account_id, tunnel_id, &config)
        .await
        .with_context(|| format!("writing ingress configuration of tunnel {tunnel_id}"))?;
    info!(
        tunnel_id,
        rules = plan.rules.len(),
        "tunnel ingress configuration updated"
    );
    Ok(TunnelIngressOutcome::Updated)
}

/// Resolve Cloudflare credentials from the mirror's own provider slot and
/// publish `plan`'s rules to `tunnel_id`.
///
/// The apply-layer entry point: credentials come from
/// `.yah/infra/providers/<provider_id>.toml` (the slot's `use = "…"`), the same
/// route [`ensure_r2_custom_domain`](super::domain::ensure_r2_custom_domain)
/// takes, so a mirror never has to name its account twice.
pub async fn publish_tunnel_ingress(
    workspace_root: &std::path::Path,
    provider_id: &str,
    tunnel_id: &str,
    plan: &IngressPlan,
) -> Result<TunnelIngressOutcome> {
    let cf_provider = super::cf_creds::CfProvider::resolve(workspace_root, provider_id)?;
    let account_id = cf_provider.account_id.clone();
    let cf = CloudflareClient::new(cf_provider.api_token()?);
    ensure_tunnel_ingress(&cf, &account_id, tunnel_id, plan).await
}

/// Result of an [`ensure_tunnel_ingress`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelIngressOutcome {
    /// Live config already published every planned rule — no write made.
    AlreadyCurrent,
    /// The tunnel's ingress config was rewritten.
    Updated,
}

/// Merge planned rules into a tunnel's live ingress list.
///
/// cloudflared requires the list to end with a catch-all rule (no `hostname`);
/// everything before it is matched top-down. So:
///
/// - a live rule whose hostname this plan owns is **replaced** (the plan is
///   authoritative for its own hostnames);
/// - a live rule for any other hostname is **kept verbatim**, including fields
///   this crate does not model (`path`, `originRequest`, …) — one tunnel fans
///   in every service on the node, and stomping a neighbour's rule because we
///   don't parse its options would take that service down;
/// - the live catch-all is preserved if present, else `http_status:404` is
///   appended.
fn merge_tunnel_ingress(live: &[Value], rules: &[IngressRule]) -> Result<Vec<Value>> {
    let owned: std::collections::BTreeSet<&str> =
        rules.iter().map(|r| r.hostname.as_str()).collect();

    let mut out: Vec<Value> = Vec::with_capacity(live.len() + rules.len());
    let mut catch_all: Option<Value> = None;

    for rule in live {
        match rule.get("hostname").and_then(Value::as_str) {
            // The trailing catch-all — hold it back so it stays last.
            None | Some("") => catch_all = Some(rule.clone()),
            Some(host) if owned.contains(host) => {} // replaced below
            Some(_) => out.push(rule.clone()),
        }
    }

    for rule in rules {
        out.push(json!({
            "hostname": rule.hostname,
            "service": rule.service_url()?,
        }));
    }

    out.push(catch_all.unwrap_or_else(|| json!({ "service": "http_status:404" })));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MirrorShape;
    use std::collections::BTreeMap;

    fn mirror(ingress: IngressProvider, slots: &str) -> MirrorConfig {
        let providers: BTreeMap<String, crate::MirrorProviderSlot> =
            toml::from_str(slots).expect("slot fixture parses");
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            ingress,
            providers,
            drivers: Default::default(),
            asset_aliases: Default::default(),
        }
    }

    // ── plan_ingress ──

    #[test]
    fn no_ingress_field_plans_nothing() {
        let m = mirror(
            IngressProvider::None,
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        assert!(declared(&m).is_none());
        assert_eq!(plan_ingress(&m).unwrap(), None);
    }

    #[test]
    fn derives_a_rule_per_fronted_slot_sorted_by_hostname() {
        let m = mirror(
            IngressProvider::CloudflareTunnel,
            "[compute]\nuse = \"hetzner\"\nmachine = \"us-east-001\"\nzone = \"z.yah.dev\"\nport = 8080\n\
             [receiver]\nuse = \"cloudflare\"\nzone = \"a.yah.dev\"\nport = 9090\n",
        );
        let plan = plan_ingress(&m).unwrap().unwrap();
        assert_eq!(plan.provider, IngressProvider::CloudflareTunnel);
        assert_eq!(
            plan.rules,
            vec![
                IngressRule {
                    hostname: "a.yah.dev".into(),
                    port: 9090,
                    slot: "receiver".into(),
                    provider_id: Some("cloudflare".into()),
                    machine: None,
                    upstream_host: None,
                },
                IngressRule {
                    hostname: "z.yah.dev".into(),
                    port: 8080,
                    slot: "compute".into(),
                    provider_id: Some("hetzner".into()),
                    machine: Some("us-east-001".into()),
                    upstream_host: None,
                },
            ]
        );
        // Credentials + placement are read off the slots, not asked for twice.
        assert_eq!(plan.provider_id(), Some("cloudflare"));
        assert_eq!(plan.machine(), Some("us-east-001"));
    }

    #[test]
    fn slot_without_the_opt_in_marker_is_skipped() {
        let m = mirror(
            IngressProvider::Passway,
            "[static]\nuse = \"cloudflare\"\nbucket = \"b\"\n\
             [compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = plan_ingress(&m).unwrap().unwrap();
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].slot, "compute");
    }

    #[test]
    fn a_cdn_slots_zone_does_not_drag_it_into_the_plan() {
        // The real shape of .yah/services/yah-analytics/mirrors/cloud.toml: a
        // CDN-published static tier carries `zone` meaning the *Cloudflare
        // zone*, not a front door. Keying participation off `zone` would fail
        // this mirror's apply the moment `ingress` was declared.
        let m = mirror(
            IngressProvider::CloudflareTunnel,
            "[static]\nuse = \"cloudflare\"\nbucket = \"yah-app-dev\"\n\
             zone = \"analytics.yah.dev\"\n\
             [compute]\nuse = \"hetzner\"\nmachine = \"yah-cloud-1\"\n\
             zone = \"analytics.yah.dev\"\nport = 8080\n",
        );
        let plan = plan_ingress(&m).unwrap().unwrap();
        assert_eq!(plan.rules.len(), 1, "only the opted-in slot is fronted");
        assert_eq!(plan.rules[0].slot, "compute");
    }

    #[test]
    fn opt_in_without_zone_is_an_error_naming_the_slot() {
        let m = mirror(
            IngressProvider::CloudflareTunnel,
            "[compute]\nuse = \"hetzner\"\nport = 8080\n",
        );
        let err = plan_ingress(&m).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("providers.compute"), "got: {msg}");
        assert!(msg.contains("zone"), "got: {msg}");
    }

    #[test]
    fn ingress_with_no_fronted_slot_is_an_error() {
        let m = mirror(
            IngressProvider::Passway,
            "[static]\nuse = \"cloudflare\"\nbucket = \"b\"\n",
        );
        let err = plan_ingress(&m).unwrap_err();
        assert!(format!("{err:#}").contains("no provider slot declares `port`"));
    }

    // ── the swap the seam exists for ──

    #[test]
    fn same_mirror_plans_identical_rules_under_either_provider() {
        let slots = "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n";
        let tunnel = plan_ingress(&mirror(IngressProvider::CloudflareTunnel, slots))
            .unwrap()
            .unwrap();
        let passway = plan_ingress(&mirror(IngressProvider::Passway, slots))
            .unwrap()
            .unwrap();
        // Only the provider tag differs — flipping the field is the whole edit.
        assert_ne!(tunnel.provider, passway.provider);
        assert_eq!(tunnel.rules, passway.rules);
    }

    #[test]
    fn renders_both_provider_forms_from_one_rule() {
        let r = rule("a.yah.dev", 8080);
        assert_eq!(r.service_url().unwrap(), "http://100.64.0.5:8080");
        assert_eq!(r.passway_upstream().unwrap(), "a.yah.dev=100.64.0.5:8080");
    }

    // ── resolve_upstreams (R599-F12: no loopback default) ──

    #[test]
    fn an_unresolved_rule_renders_nothing_rather_than_dialing_loopback() {
        let m = mirror(
            IngressProvider::CloudflareTunnel,
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = plan_ingress(&m).unwrap().unwrap();
        // Before R599-F12 this silently produced http://127.0.0.1:8080 and the
        // failure only showed up as a 502 at request time.
        let err = plan.rules[0].service_url().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("service-records"), "got: {msg}");
        assert!(msg.contains("upstream_host"), "got: {msg}");
    }

    #[test]
    fn discovery_fills_the_upstream_from_placement() {
        let m = mirror(
            IngressProvider::Passway,
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let mut plan = plan_ingress(&m).unwrap().unwrap();
        plan.resolve_upstreams(|r| {
            assert_eq!(r.port, 8080);
            Ok(Some("100.64.0.7".into()))
        })
        .unwrap();
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["a.yah.dev=100.64.0.7:8080"]
        );
    }

    #[test]
    fn an_explicit_upstream_host_wins_over_discovery() {
        let m = mirror(
            IngressProvider::Passway,
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n\
             upstream_host = \"127.0.0.1\"\n",
        );
        let mut plan = plan_ingress(&m).unwrap().unwrap();
        plan.resolve_upstreams(|_| panic!("discovery must not run for a pinned slot"))
            .unwrap();
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["a.yah.dev=127.0.0.1:8080"]
        );
    }

    #[test]
    fn no_ready_record_is_an_error_not_an_empty_upstream() {
        let m = mirror(
            IngressProvider::CloudflareTunnel,
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let mut plan = plan_ingress(&m).unwrap().unwrap();
        let err = plan.resolve_upstreams(|_| Ok(None)).unwrap_err();
        assert!(format!("{err:#}").contains("no resolved upstream address"));
    }

    // ── merge_tunnel_ingress ──

    /// A rule with its upstream already resolved to a mesh address — what a
    /// plan looks like after `resolve_upstreams`.
    fn rule(hostname: &str, port: u16) -> IngressRule {
        IngressRule {
            hostname: hostname.into(),
            port,
            slot: "compute".into(),
            provider_id: None,
            machine: None,
            upstream_host: Some("100.64.0.5".into()),
        }
    }

    #[test]
    fn merge_appends_catch_all_when_tunnel_is_empty() {
        let out = merge_tunnel_ingress(&[], &[rule("a.yah.dev", 8080)]).unwrap();
        assert_eq!(
            out,
            vec![
                json!({"hostname": "a.yah.dev", "service": "http://100.64.0.5:8080"}),
                json!({"service": "http_status:404"}),
            ]
        );
    }

    #[test]
    fn merge_keeps_a_neighbours_rule_verbatim_including_unmodelled_fields() {
        let live = vec![
            json!({
                "hostname": "other.yah.dev",
                "service": "http://127.0.0.1:9999",
                "path": "/api/*",
                "originRequest": {"noTLSVerify": true}
            }),
            json!({"service": "http_status:404"}),
        ];
        let out = merge_tunnel_ingress(&live, &[rule("a.yah.dev", 8080)]).unwrap();
        assert_eq!(
            out[0], live[0],
            "neighbour rule must survive byte-identical"
        );
        assert_eq!(
            out[1],
            json!({"hostname": "a.yah.dev", "service": "http://100.64.0.5:8080"})
        );
        assert_eq!(out[2], json!({"service": "http_status:404"}));
    }

    #[test]
    fn merge_replaces_an_owned_hostname_and_keeps_the_live_catch_all() {
        let live = vec![
            json!({"hostname": "a.yah.dev", "service": "http://127.0.0.1:1111"}),
            json!({"service": "http_status:503"}),
        ];
        let out = merge_tunnel_ingress(&live, &[rule("a.yah.dev", 8080)]).unwrap();
        assert_eq!(
            out,
            vec![
                json!({"hostname": "a.yah.dev", "service": "http://100.64.0.5:8080"}),
                json!({"service": "http_status:503"}),
            ]
        );
    }

    #[test]
    fn merge_is_idempotent() {
        let rules = vec![rule("a.yah.dev", 8080)];
        let once = merge_tunnel_ingress(&[], &rules).unwrap();
        let twice = merge_tunnel_ingress(&once, &rules).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn merge_treats_empty_hostname_as_the_catch_all() {
        // Cloudflare renders the trailing rule with `hostname: ""` in some
        // responses; it must not be mistaken for a routable hostname.
        let live = vec![json!({"hostname": "", "service": "http_status:404"})];
        let out = merge_tunnel_ingress(&live, &[rule("a.yah.dev", 8080)]).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[1],
            json!({"hostname": "", "service": "http_status:404"})
        );
    }
}
