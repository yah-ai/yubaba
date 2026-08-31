//! Public-ingress provider seam — `mirror.ingress` → live front-door state.
//!
//! Part of R594-F11 (W267 §"Ingress is a provider, not a fixed part of the
//! stack"). The canonical ticket annotation lives in
//! `.yah/docs/working/W267-sovereign-public-ingress.md`.
//!
//! A mirror declares a **list of edges**
//! ([`IngressEdge`](crate::config::IngressEdge)) and the rules each one needs
//! published are derived, not typed in:
//!
//! ```text
//! slots with `zone` + `port`  ─partitioned by edge selector─►  IngressPlan { provider, rules, front_doors }
//!                                           ├── cloudflare-tunnel → CF API ingress config
//!                                           └── passway           → PASSWAY_UPSTREAMS
//! ```
//!
//! [`plan_ingress`] is pure and provider-agnostic on purpose: the same
//! `(hostname, port)` pairs feed either arm, so flipping
//! `ingress = "cloudflare-tunnel"` to `ingress = "passway"` needs no other edit
//! to the mirror. That is the whole point of calling ingress a *provider* —
//! walking W267's tier ladder is a config flip, not a rewrite. W305 F2 makes
//! that ladder *per edge*: a mirror can now front its public web tier through
//! cloudflare and an internal tier through passway, which a single
//! [`IngressProvider`](crate::config::IngressProvider) field could not express.
//!
//! **The node's front doors are collated, not declared.** An edge invokes a
//! per-node appliance, but that is downstream of the service's declaration:
//! [`collate_front_doors`] takes every service's plans and derives what each
//! node must run. That direction is the whole point — declaring cohorts
//! node-side (W267 Gap 3) produces two sources of truth for one fact, and the
//! node's copy is the one that goes stale.
//!
//! **The provider owns addressing, never rendering.** A rule carries a
//! hostname and a local port — enough to *dial*, and deliberately nothing about
//! what any path means. The W173 render cube stays in mesofact's manifest
//! (W267 §"Two front doors, one render contract"); growing a path-based router
//! here would mint a third copy of those rules.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tracing::{debug, info};

use crate::config::{resolve_machine_among, IngressEdge, IngressProvider};
use crate::{CloudflareClient, MachineConfig, MirrorConfig};

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
/// Plural spelling of [`MACHINE_FIELD`], used by placement-list slots such as
/// `[providers.bundle]`. Read as a fallback so a bundle tier is plannable at
/// all — before this, `machines = ["us-east-001"]` was invisible to the planner
/// and every rule derived from a bundle slot resolved no upstream.
///
/// Only the first entry is used: this names the node upstream **discovery** is
/// aimed at, and a workload placed on several nodes still answers on any one of
/// them. Front-door placement is a different question with its own field —
/// `MirrorConfig::ingress_machines`.
const MACHINES_FIELD: &str = "machines";
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

/// What **one declared edge** has to publish.
///
/// A mirror yields one of these per [`IngressEdge`](crate::config::IngressEdge)
/// it declares, with the fronted rules partitioned across them — so two plans
/// from one mirror never publish the same hostname through two front doors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressPlan {
    pub provider: IngressProvider,
    /// Derived rules, ordered by hostname so a plan is stable across runs and
    /// two applies produce byte-identical config.
    pub rules: Vec<IngressRule>,
    /// Machines the front door is placed on (R330-F37), in declaration order.
    ///
    /// Never empty when the mirror declares an ingress provider *and* the
    /// fronted slot names a machine: it falls back to that one machine, which
    /// is the co-located shape every mirror had before this field existed. It
    /// **is** empty when neither is declared, and each provider arm decides
    /// whether that is an error (the tunnel arm) or a placeholder (passway's
    /// rendered deploy line).
    pub front_doors: Vec<String>,
    /// Cloudflare Tunnel id this edge declared, overriding the fronting
    /// machine's own (W267 Gap 3). `None` means "use the node's" — the common
    /// case, and the only shape that existed before W305 F2.
    pub tunnel_id: Option<String>,
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

    /// Machine the fronted **workload** runs on — the `machine` / `machines`
    /// of the first fronted slot that names one.
    ///
    /// This is the node upstream discovery is aimed at, and it is *not* where
    /// the front door goes: see [`front_doors`](Self::front_doors). Conflating
    /// the two is what made co-location structural — an ingress node was
    /// obliged to host every service it fronted, so the ingress tier could
    /// never be wider than the service tier.
    pub fn workload_machine(&self) -> Option<&str> {
        self.rules.iter().find_map(|r| r.machine.as_deref())
    }
}

/// The edges this mirror declares — empty when it has none.
///
/// The dispatch-layer predicate, mirroring
/// [`mesofact_bundle::slot_declared`](super::mesofact_bundle::slot_declared):
/// checked before any provider-specific work runs.
pub fn declared(mirror: &MirrorConfig) -> Result<Vec<IngressEdge>> {
    mirror.ingress_edges()
}

/// Resolve the machine each provider slot's `required = { … }` constraint
/// (F16 placement) implies, for slots that declare no literal `machine` /
/// `machines` field (R772).
///
/// [`plan_ingress`] cannot do this itself — it is deliberately pure, with no
/// view of `.yah/infra/machines/`, which is what lets `xtask/tests/
/// mirror_ingress.rs` plan the real tree as a unit test with no config tree to
/// build. So the caller resolves placements *first*, against the machines it
/// already has, and hands the result to `plan_ingress` as data — the same
/// shape [`IngressPlan::resolve_upstreams`] already uses for discovery. This
/// is what makes `providers.bundle.required = { regions, mesh_tags }`
/// plannable at all: before this existed, replacing a bundle slot's literal
/// `machines` with a constraint took `IngressPlan::workload_machine()` from
/// `Some(node)` to `None`, silently un-aiming upstream discovery — measured on
/// `.yah/services/yah-marketing/mirrors/cloud.toml`'s bundle slot, which now
/// uses this fallback for real.
///
/// Takes `&[MachineConfig]` rather than a full `CloudConfig` deliberately: a
/// caller collating every mirror in the workspace (`collate_workspace_ingress`)
/// has no business hard-failing over an unrelated mirror's
/// `providers.X.use = "<id>"` typo, which a full `CloudConfig::load` would do.
///
/// A slot with a literal `machine` / `machines` field is left alone — that
/// field wins in [`plan_ingress`] regardless of what this returns. Only a slot
/// with `required` and no literal placement is resolved, and a match failure
/// is a loud error naming the slot: a front door whose workload cannot be
/// placed is exactly the silent-trap shape this exists to close.
pub fn resolve_ingress_placements(
    machines: &[MachineConfig],
    mirror: &MirrorConfig,
) -> Result<HashMap<String, String>> {
    let mut placements = HashMap::new();
    for (role, slot) in &mirror.providers {
        let fields = slot.fields();
        if fields.contains_key(MACHINE_FIELD) || fields.contains_key(MACHINES_FIELD) {
            continue;
        }
        let Some(required) = slot.required() else {
            continue;
        };
        let machine = resolve_machine_among(machines, &required).with_context(|| {
            format!("resolving placement for [providers.{role}] required = {{ … }}")
        })?;
        placements.insert(role.clone(), machine.name.clone());
    }
    Ok(placements)
}

/// Derive every declared edge's rules from the mirror's provider slots.
///
/// A slot participates when it declares `port`; its `zone` is the public
/// hostname that port is fanned in at. `port` without a `zone` is an **error**,
/// not a skip — a mirror that declares a front door and a fronted port but no
/// hostname is always a typo, and silently dropping it is exactly the failure
/// mode where an operator flips `ingress = "cloudflare-tunnel"` and gets a
/// front door that publishes nothing. A slot with `zone` and no `port` is
/// skipped: that is a CDN-published tier, not a fronted one.
///
/// `placements` is the pre-resolved output of [`resolve_ingress_placements`] —
/// a fallback for a slot's `machine` field when the slot declares `required`
/// instead of a literal placement. Pass `&HashMap::new()` for a mirror with no
/// constraint-based slots (every slot on disk today, save the one this fallback
/// exists for).
///
/// The derived rules are then **partitioned** across the declared edges by
/// their `slots` / `hostnames` selectors. The partition is required to be total
/// and disjoint (W305 F2): a fronted slot claimed by no edge, or by two, is an
/// error naming both sides. Neither has a safe default — dropping the slot
/// publishes nothing at a hostname the operator declared, and picking one of
/// two edges silently sends a service out through the wrong front door.
///
/// Returns an empty vec when the mirror declares no ingress edge. Plans are in
/// declaration order.
pub fn plan_ingress(
    mirror: &MirrorConfig,
    placements: &HashMap<String, String>,
) -> Result<Vec<IngressPlan>> {
    let edges = declared(mirror)?;
    if edges.is_empty() {
        return Ok(Vec::new());
    }

    let mut rules = Vec::new();
    for (role, slot) in &mirror.providers {
        let fields = slot.fields();
        let Some(port) = fields.get(PORT_FIELD).and_then(|v| v.as_integer()) else {
            continue;
        };
        let Some(zone) = fields.get(ZONE_FIELD).and_then(|v| v.as_str()) else {
            bail!(
                "mirror declares {} ingress edge(s) and slot [providers.{role}] declares \
                 {PORT_FIELD} = {port}, but no `zone` — an ingress provider fans a public \
                 hostname in to a node-local port, so it has nothing to publish that port \
                 at. Add `zone = \"<hostname>\"` to the slot, or drop `{PORT_FIELD}` if \
                 this slot is not fronted.",
                edges.len()
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
                .map(str::to_string)
                .or_else(|| {
                    fields
                        .get(MACHINES_FIELD)
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .or_else(|| placements.get(role).cloned()),
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
            "mirror declares {} ingress edge(s) but no provider slot declares `{PORT_FIELD}` — \
             there is nothing to publish. Either add `zone` + `{PORT_FIELD}` to the slot \
             the front door fronts, or remove the `ingress` declaration.",
            edges.len()
        );
    }

    // A selectorless edge claims everything, which can only be unambiguous when
    // it is the mirror's only one. Two front doors and no way to tell which
    // fronts what is the shape this ticket exists to make expressible — so it
    // has to be *stated*, not resolved by declaration order.
    if edges.len() > 1 {
        if let Some(edge) = edges.iter().find(|e| !e.has_selector()) {
            bail!(
                "{}: a mirror with {} edges needs every edge to name what it fronts. Add \
                 `slots = [...]` or `hostnames = [...]`. Mixing front doors is the whole point \
                 of declaring several, and an implicit catch-all would publish a service \
                 through whichever edge happened to be written first.",
                edge.label(),
                edges.len()
            );
        }
    }

    partition(&edges, rules)
}

/// Split derived rules across declared edges, one [`IngressPlan`] each.
///
/// Total and disjoint by construction: every rule lands in exactly one plan or
/// this errors. Preserves declaration order so `yah cloud apply` reports edges
/// in the order the operator wrote them.
fn partition(edges: &[IngressEdge], rules: Vec<IngressRule>) -> Result<Vec<IngressPlan>> {
    let mut buckets: Vec<Vec<IngressRule>> = vec![Vec::new(); edges.len()];

    for rule in rules {
        let claimants: Vec<usize> = edges
            .iter()
            .enumerate()
            .filter(|(_, e)| e.claims(&rule.slot, &rule.hostname))
            .map(|(i, _)| i)
            .collect();

        match claimants.as_slice() {
            [i] => buckets[*i].push(rule),
            [] => bail!(
                "slot [providers.{}] is fronted at {:?} but no `[[ingress]]` edge claims it — \
                 the partition has a hole, so that hostname would be published by nothing while \
                 the declaration says otherwise. Add {:?} to an edge's `slots`, or {:?} to its \
                 `hostnames`.",
                rule.slot,
                rule.hostname,
                rule.slot,
                rule.hostname
            ),
            many => bail!(
                "slot [providers.{}] ({:?}) is claimed by {} edges — {}. One hostname cannot be \
                 published through two front doors: DNS points one way, so the second is dead \
                 config that looks live. Narrow the selectors so exactly one claims it.",
                rule.slot,
                rule.hostname,
                many.len(),
                many.iter()
                    .map(|i| edges[*i].label())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        }
    }

    let mut plans = Vec::with_capacity(edges.len());
    for (edge, rules) in edges.iter().zip(buckets) {
        if rules.is_empty() {
            bail!(
                "{}: fronts nothing. Its selector matches no slot that declares `zone` + \
                 `{PORT_FIELD}` — a typo'd slot name is otherwise invisible, because the front \
                 door still deploys and simply publishes an empty rule set.",
                edge.label()
            );
        }
        // Front-door placement: the edge's own list wins, and falls back to the
        // fronted workload's own node — the co-located shape, which stays the
        // default because it is what every mirror written before this field
        // meant.
        let front_doors = if edge.machines.is_empty() {
            rules
                .iter()
                .find_map(|r| r.machine.clone())
                .into_iter()
                .collect()
        } else {
            edge.machines.clone()
        };
        plans.push(IngressPlan {
            provider: edge.provider,
            rules,
            front_doors,
            tunnel_id: edge.tunnel_id.clone(),
        });
    }
    Ok(plans)
}

// ── collation: what each NODE must run (W305 F2) ─────────────────────────────

/// One service's planned edge, tagged with where it was declared.
///
/// The collator's input unit. Carrying `(service, env)` is not decoration: a
/// collated front door is derived from several services at once, so every
/// conflict has to be able to name which declarations disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEdge {
    pub service: String,
    pub env: String,
    pub plan: IngressPlan,
}

impl PlannedEdge {
    /// `service/env`, the label every collation message points at.
    pub fn label(&self) -> String {
        format!("{}/{}", self.service, self.env)
    }
}

/// One front-door appliance a node has to run, derived from every service edge
/// that fronts through it.
///
/// **Nothing declares this.** It is a pure function of the services' `[[ingress]]`
/// edges, which is the direction W305 F2 fixes: the node used to carry its own
/// `cloudflared` cohort declaration (W267 Gap 3) and there was no mechanism
/// making the two agree. A derived view cannot disagree with its inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFrontDoor {
    /// Machine the appliance runs on.
    pub machine: String,
    /// Which appliance — one passway or one cloudflared per (machine, cohort).
    pub provider: IngressProvider,
    /// Tunnel id for the rented arm when an edge named one, else `None` meaning
    /// "the node's own `MachineConfig.cloudflared`". Part of the grouping key:
    /// a node fronting two cohorts runs two connectors, which is exactly the
    /// case Gap 3 could not model.
    pub tunnel_id: Option<String>,
    /// The union of every fronting edge's rules, ordered by hostname.
    pub rules: Vec<IngressRule>,
    /// `service/env` labels that contributed, in sorted order — the provenance
    /// an operator needs to answer "why is this hostname on this box".
    pub sources: Vec<String>,
}

impl NodeFrontDoor {
    /// The whole appliance's `PASSWAY_UPSTREAMS` set — every service fronting
    /// through this node, in one env var. This is the fan-in the per-node
    /// process was always doing implicitly; collation is what makes it
    /// computable before the deploy rather than observable after it.
    pub fn passway_upstreams(&self) -> Result<Vec<String>> {
        self.rules.iter().map(IngressRule::passway_upstream).collect()
    }
}

/// What every node in the camp must run, plus the edges nothing could place.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collation {
    /// Front doors, sorted by `(machine, provider, tunnel_id)`.
    pub front_doors: Vec<NodeFrontDoor>,
    /// Labels of declared edges with no machine to run on — neither the edge's
    /// own `machines` nor the fronted slot's placement named one. Returned
    /// rather than dropped: an edge that collates onto no node publishes
    /// nothing, and that is invisible from the mirror that declared it.
    pub unplaced: Vec<String>,
}

/// Collate every service's planned edges into the per-node front doors they
/// imply (W305 F2).
///
/// Grouped by `(machine, provider, tunnel_id)` — one appliance per cohort per
/// node, which is the fan-in argument
/// [`MirrorConfig::ingress`](crate::MirrorConfig::ingress) already makes, now
/// applied *across* services instead of within one.
///
/// Two conflicts are rejected, both of which are today invisible because each
/// service's apply only ever sees its own mirror:
///
/// 1. **One hostname, two providers.** DNS points one way, so the second
///    declaration is dead config that reads as live.
/// 2. **One hostname, two upstreams.** Whichever service applied last wins on
///    the box, so the front door's behaviour depends on apply order.
///
/// Deterministic: front doors sorted by key, rules by hostname, sources sorted.
pub fn collate_front_doors(planned: &[PlannedEdge]) -> Result<Collation> {
    // Conflict pass first — a conflicting declaration must not produce a
    // half-built collation that a caller might act on.
    let mut owner: std::collections::BTreeMap<&str, (&PlannedEdge, &IngressRule)> =
        std::collections::BTreeMap::new();
    for edge in planned {
        for rule in &edge.plan.rules {
            match owner.get(rule.hostname.as_str()) {
                None => {
                    owner.insert(rule.hostname.as_str(), (edge, rule));
                }
                Some((first_edge, first_rule)) => {
                    if first_edge.plan.provider != edge.plan.provider {
                        bail!(
                            "hostname {:?} is fronted by two different providers — {} declares \
                             {:?} and {} declares {:?}. DNS points one way, so one of them is \
                             dead config that still reads as live. Pick one front door for that \
                             hostname.",
                            rule.hostname,
                            first_edge.label(),
                            first_edge.plan.provider.as_str(),
                            edge.label(),
                            edge.plan.provider.as_str()
                        );
                    }
                    if (first_rule.port, &first_rule.upstream_host)
                        != (rule.port, &rule.upstream_host)
                    {
                        bail!(
                            "hostname {:?} is fronted at two different upstreams — {} \
                             (providers.{}, port {}) and {} (providers.{}, port {}). One front \
                             door publishes one rule per hostname, so whichever service applies \
                             last wins on the box.",
                            rule.hostname,
                            first_edge.label(),
                            first_rule.slot,
                            first_rule.port,
                            edge.label(),
                            rule.slot,
                            rule.port
                        );
                    }
                }
            }
        }
    }

    type Key = (String, &'static str, Option<String>);
    let mut grouped: std::collections::BTreeMap<Key, NodeFrontDoor> =
        std::collections::BTreeMap::new();
    let mut unplaced = Vec::new();

    for edge in planned {
        if edge.plan.front_doors.is_empty() {
            unplaced.push(edge.label());
            continue;
        }
        for machine in &edge.plan.front_doors {
            let key: Key = (
                machine.clone(),
                edge.plan.provider.as_str(),
                edge.plan.tunnel_id.clone(),
            );
            let door = grouped.entry(key).or_insert_with(|| NodeFrontDoor {
                machine: machine.clone(),
                provider: edge.plan.provider,
                tunnel_id: edge.plan.tunnel_id.clone(),
                rules: Vec::new(),
                sources: Vec::new(),
            });
            for rule in &edge.plan.rules {
                // The same (service, env) can reach one node through several
                // edges; the conflict pass has already proven identical
                // hostnames carry identical rules, so dedup is safe here.
                if !door.rules.iter().any(|r| r.hostname == rule.hostname) {
                    door.rules.push(rule.clone());
                }
            }
            let label = edge.label();
            if !door.sources.contains(&label) {
                door.sources.push(label);
            }
        }
    }

    let mut front_doors: Vec<NodeFrontDoor> = grouped.into_values().collect();
    for door in &mut front_doors {
        door.rules.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        door.sources.sort();
    }
    unplaced.sort();
    unplaced.dedup();

    Ok(Collation {
        front_doors,
        unplaced,
    })
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
        mirror_placed(ingress, &[], slots)
    }

    /// [`mirror`] with an explicit front-door placement list (R330-F37) — the
    /// legacy single-edge spelling, `ingress` + `ingress_machines`.
    fn mirror_placed(
        ingress: IngressProvider,
        ingress_machines: &[&str],
        slots: &str,
    ) -> MirrorConfig {
        let mut m = mirror_edges(vec![], slots);
        m.ingress = ingress.into();
        m.ingress_machines = ingress_machines.iter().map(|s| s.to_string()).collect();
        m
    }

    /// A mirror declaring `[[ingress]]` edges (W305 F2).
    fn mirror_edges(edges: Vec<IngressEdge>, slots: &str) -> MirrorConfig {
        let providers: BTreeMap<String, crate::MirrorProviderSlot> =
            toml::from_str(slots).expect("slot fixture parses");
        MirrorConfig {
            schema_version: 1,
            shape: MirrorShape::SingleMachine,
            ingress: crate::config::IngressDecl::Edges(edges),
            ingress_machines: Vec::new(),
            providers,
            drivers: Default::default(),
            asset_aliases: Default::default(),
        }
    }

    /// One edge, spelled the way an operator writes it in TOML.
    fn edge(provider: IngressProvider, machines: &[&str], slots: &[&str]) -> IngressEdge {
        IngressEdge {
            provider,
            machines: machines.iter().map(|s| s.to_string()).collect(),
            slots: slots.iter().map(|s| s.to_string()).collect(),
            hostnames: Vec::new(),
            tunnel_id: None,
        }
    }

    /// The single plan a one-edge mirror yields.
    fn only_plan(m: &MirrorConfig) -> IngressPlan {
        let mut plans = plan_ingress(m, &HashMap::new()).expect("mirror plans");
        assert_eq!(plans.len(), 1, "fixture declares exactly one edge");
        plans.remove(0)
    }

    // ── plan_ingress ──

    #[test]
    fn no_ingress_field_plans_nothing() {
        let m = mirror(
            IngressProvider::None,
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        assert!(declared(&m).unwrap().is_empty());
        assert_eq!(plan_ingress(&m, &HashMap::new()).unwrap(), vec![]);
    }

    #[test]
    fn derives_a_rule_per_fronted_slot_sorted_by_hostname() {
        let m = mirror(
            IngressProvider::CloudflareTunnel,
            "[compute]\nuse = \"hetzner\"\nmachine = \"us-east-001\"\nzone = \"z.yah.dev\"\nport = 8080\n\
             [receiver]\nuse = \"cloudflare\"\nzone = \"a.yah.dev\"\nport = 9090\n",
        );
        let plan = only_plan(&m);
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
        assert_eq!(plan.workload_machine(), Some("us-east-001"));
        // With no `ingress_machines`, the front door falls back to the fronted
        // workload's node — the co-located shape every mirror had before.
        assert_eq!(plan.front_doors, vec!["us-east-001".to_string()]);
    }

    #[test]
    fn slot_without_the_opt_in_marker_is_skipped() {
        let m = mirror(
            IngressProvider::Passway,
            "[static]\nuse = \"cloudflare\"\nbucket = \"b\"\n\
             [compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
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
        let plan = only_plan(&m);
        assert_eq!(plan.rules.len(), 1, "only the opted-in slot is fronted");
        assert_eq!(plan.rules[0].slot, "compute");
    }

    #[test]
    fn opt_in_without_zone_is_an_error_naming_the_slot() {
        let m = mirror(
            IngressProvider::CloudflareTunnel,
            "[compute]\nuse = \"hetzner\"\nport = 8080\n",
        );
        let err = plan_ingress(&m, &HashMap::new()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("providers.compute"), "got: {msg}");
        assert!(msg.contains("zone"), "got: {msg}");
    }

    // ── front-door placement (R330-F37) ──

    #[test]
    fn front_doors_are_independent_of_where_the_fronted_workload_runs() {
        // The whole point of the field: N front doors over ONE deployment. The
        // workload stays pinned to east; the ingress tier spans east + west.
        let m = mirror_placed(
            IngressProvider::Passway,
            &["us-east-001", "us-west-001"],
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\nupstream_host = \"100.64.0.3\"\n",
        );
        let plan = only_plan(&m);
        assert_eq!(
            plan.front_doors,
            vec!["us-east-001".to_string(), "us-west-001".to_string()]
        );
        // …and the workload placement is untouched, so discovery still asks the
        // node that actually holds the deployment.
        assert_eq!(plan.workload_machine(), Some("us-east-001"));
    }

    #[test]
    fn a_bundle_slots_machines_list_is_read_as_placement() {
        // `[providers.bundle]` spells placement `machines`, not `machine`.
        // Before R330-F37 the planner only read the singular, so every rule
        // derived from a bundle slot had `machine: None` and discovery had no
        // node to ask.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\", \"us-west-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.rules[0].machine.as_deref(), Some("us-east-001"));
        assert_eq!(plan.front_doors, vec!["us-east-001".to_string()]);
    }

    #[test]
    fn a_singular_machine_field_still_wins_over_the_plural_one() {
        let m = mirror(
            IngressProvider::Passway,
            "[compute]\nuse = \"hetzner\"\nmachine = \"pinned\"\n\
             machines = [\"ignored\"]\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.rules[0].machine.as_deref(), Some("pinned"));
    }

    #[test]
    fn front_door_placement_without_a_front_door_is_an_error() {
        // A silent skip here is the same failure as `port` with no `zone`: the
        // operator names placement, gets nothing, and nothing says why.
        let m = mirror_placed(
            IngressProvider::None,
            &["us-west-001"],
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let err = plan_ingress(&m, &HashMap::new()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ingress_machines"), "got: {msg}");
        assert!(msg.contains("us-west-001"), "got: {msg}");
    }

    #[test]
    fn every_front_door_gets_the_same_upstream_set() {
        // Fanning the front door out must not fan the *rules* out — one
        // rendered copy of the site, so no cache coherence to settle. The plan
        // is shared across placements by construction; this pins that the
        // upstream set is a property of the plan, not of a placement.
        let m = mirror_placed(
            IngressProvider::Passway,
            &["us-east-001", "us-west-001", "us-south-001"],
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\nupstream_host = \"100.64.0.3\"\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.front_doors.len(), 3);
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.3:8080".to_string()]
        );
    }

    #[test]
    fn ingress_with_no_fronted_slot_is_an_error() {
        let m = mirror(
            IngressProvider::Passway,
            "[static]\nuse = \"cloudflare\"\nbucket = \"b\"\n",
        );
        let err = plan_ingress(&m, &HashMap::new()).unwrap_err();
        assert!(format!("{err:#}").contains("no provider slot declares `port`"));
    }


    // ── declared edges (W305 F2) ──

    /// The whole reason the field became a list: one mirror, two front doors.
    const MIXED_SLOTS: &str = "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
         zone = \"yah.dev\"\nport = 8080\nupstream_host = \"100.64.0.3\"\n\
         [internal]\nuse = \"hetzner\"\nmachine = \"us-west-001\"\n\
         zone = \"admin.yah.dev\"\nport = 9443\nupstream_host = \"100.64.0.4\"\n";

    #[test]
    fn two_edges_split_the_rules_and_keep_their_own_placement() {
        let m = mirror_edges(
            vec![
                edge(IngressProvider::Passway, &["us-east-001"], &["bundle"]),
                edge(
                    IngressProvider::CloudflareTunnel,
                    &["us-west-001"],
                    &["internal"],
                ),
            ],
            MIXED_SLOTS,
        );
        let plans = plan_ingress(&m, &HashMap::new()).unwrap();
        assert_eq!(plans.len(), 2, "one plan per declared edge");

        // Declaration order, and each edge publishes only what it claims.
        assert_eq!(plans[0].provider, IngressProvider::Passway);
        assert_eq!(
            plans[0].passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.3:8080"]
        );
        assert_eq!(plans[0].front_doors, vec!["us-east-001".to_string()]);

        assert_eq!(plans[1].provider, IngressProvider::CloudflareTunnel);
        assert_eq!(plans[1].rules.len(), 1);
        assert_eq!(plans[1].rules[0].hostname, "admin.yah.dev");
        assert_eq!(plans[1].front_doors, vec!["us-west-001".to_string()]);
    }

    #[test]
    fn an_edge_may_select_by_hostname_instead_of_by_slot() {
        let m = mirror_edges(
            vec![
                IngressEdge {
                    hostnames: vec!["yah.dev".into()],
                    ..edge(IngressProvider::Passway, &["us-east-001"], &[])
                },
                IngressEdge {
                    hostnames: vec!["admin.yah.dev".into()],
                    ..edge(IngressProvider::CloudflareTunnel, &["us-west-001"], &[])
                },
            ],
            MIXED_SLOTS,
        );
        let plans = plan_ingress(&m, &HashMap::new()).unwrap();
        assert_eq!(plans[0].rules[0].hostname, "yah.dev");
        assert_eq!(plans[1].rules[0].hostname, "admin.yah.dev");
    }

    #[test]
    fn a_slot_no_edge_claims_is_an_error_naming_it() {
        // The hole this catches is invisible from the mirror: the front door
        // deploys, the site serves, and `admin.yah.dev` resolves to nothing.
        let m = mirror_edges(
            vec![
                edge(IngressProvider::Passway, &["us-east-001"], &["bundle"]),
                edge(IngressProvider::Passway, &["us-west-001"], &["nonexistent"]),
            ],
            MIXED_SLOTS,
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("internal"), "names the unclaimed slot: {msg}");
        assert!(msg.contains("admin.yah.dev"), "got: {msg}");
    }

    #[test]
    fn a_slot_two_edges_claim_is_an_error_naming_both() {
        let m = mirror_edges(
            vec![
                edge(IngressProvider::Passway, &["us-east-001"], &["bundle"]),
                IngressEdge {
                    hostnames: vec!["yah.dev".into()],
                    ..edge(IngressProvider::Passway, &["us-west-001"], &["internal"])
                },
            ],
            MIXED_SLOTS,
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("claimed by 2 edges"), "got: {msg}");
        assert!(msg.contains("slots = [\"bundle\"]"), "got: {msg}");
    }

    #[test]
    fn an_edge_whose_selector_matches_nothing_is_an_error() {
        // A typo'd slot name otherwise deploys a front door that publishes an
        // empty rule set — a working appliance serving nothing.
        let m = mirror_edges(
            vec![
                edge(IngressProvider::Passway, &["us-east-001"], &["bundle"]),
                edge(IngressProvider::Passway, &["us-west-001"], &["internl"]),
                edge(IngressProvider::Passway, &["us-south-001"], &["internal"]),
            ],
            MIXED_SLOTS,
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("fronts nothing"), "got: {msg}");
        assert!(msg.contains("internl"), "names the typo: {msg}");
    }

    #[test]
    fn several_edges_require_every_one_to_say_what_it_fronts() {
        let m = mirror_edges(
            vec![
                edge(IngressProvider::Passway, &["us-east-001"], &[]),
                edge(
                    IngressProvider::CloudflareTunnel,
                    &["us-west-001"],
                    &["internal"],
                ),
            ],
            MIXED_SLOTS,
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("needs every edge to name what it fronts"), "got: {msg}");
    }

    #[test]
    fn one_selectorless_edge_still_fronts_everything() {
        // The legacy shape, expressed as a list. It must keep meaning what
        // `ingress = "passway"` meant, or migrating a mirror silently drops
        // slots.
        let m = mirror_edges(
            vec![edge(IngressProvider::Passway, &["us-east-001"], &[])],
            MIXED_SLOTS,
        );
        let plan = only_plan(&m);
        assert_eq!(plan.rules.len(), 2);
    }

    #[test]
    fn the_legacy_scalar_spelling_plans_the_same_edge_as_the_list_form() {
        // `ingress = "passway"` + `ingress_machines` is kept as shorthand, not
        // deprecated — one service, one front door is the common case. What
        // must not happen is the two spellings drifting.
        let slots = "[compute]\nuse = \"hetzner\"\nmachine = \"us-east-001\"\n\
                     zone = \"a.yah.dev\"\nport = 8080\n";
        let scalar = only_plan(&mirror_placed(
            IngressProvider::Passway,
            &["us-east-001", "us-south-001"],
            slots,
        ));
        let listed = only_plan(&mirror_edges(
            vec![edge(
                IngressProvider::Passway,
                &["us-east-001", "us-south-001"],
                &[],
            )],
            slots,
        ));
        assert_eq!(scalar, listed);
    }

    #[test]
    fn placement_declared_twice_is_an_error_not_a_precedence_rule() {
        let mut m = mirror_edges(
            vec![edge(IngressProvider::Passway, &["us-east-001"], &[])],
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        m.ingress_machines = vec!["us-west-001".into()];
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("stated twice"), "got: {msg}");
        assert!(msg.contains("us-west-001"), "got: {msg}");
    }

    #[test]
    fn an_edge_may_name_its_own_tunnel_overriding_the_nodes() {
        // W267 Gap 3, from the service side: which cohort a service fronts
        // through is a property of the service, so a node fronting two cohorts
        // never has to enumerate them.
        let m = mirror_edges(
            vec![IngressEdge {
                tunnel_id: Some("cohort-b-tunnel".into()),
                ..edge(IngressProvider::CloudflareTunnel, &["us-east-001"], &[])
            }],
            "[compute]\nuse = \"cloudflare\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        assert_eq!(only_plan(&m).tunnel_id.as_deref(), Some("cohort-b-tunnel"));
    }

    #[test]
    fn an_edge_that_fronts_with_nothing_is_rejected() {
        let m = mirror_edges(
            vec![edge(IngressProvider::None, &["us-east-001"], &[])],
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("fronts nothing"), "got: {msg}");
    }

    #[test]
    fn both_spellings_round_trip_through_toml() {
        // The list form has to survive save/load, and the scalar form has to
        // keep parsing — every mirror on disk is written in it.
        let scalar: MirrorConfig = toml::from_str(
            "schema_version = 1\nshape = \"single-machine\"\ningress = \"passway\"\n\
             ingress_machines = [\"us-east-001\"]\n",
        )
        .expect("scalar spelling parses");
        assert_eq!(scalar.ingress_edges().unwrap().len(), 1);

        let listed: MirrorConfig = toml::from_str(
            "schema_version = 1\nshape = \"single-machine\"\n\
             [[ingress]]\nprovider = \"passway\"\nslots = [\"bundle\"]\n\
             [[ingress]]\nprovider = \"cloudflare-tunnel\"\nhostnames = [\"x.yah.dev\"]\n",
        )
        .expect("list spelling parses");
        let edges = listed.ingress_edges().unwrap();
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].slots, vec!["bundle".to_string()]);
        assert_eq!(edges[1].provider, IngressProvider::CloudflareTunnel);

        let back: MirrorConfig = toml::from_str(&toml::to_string_pretty(&listed).unwrap())
            .expect("list spelling round-trips");
        assert_eq!(back.ingress_edges().unwrap(), edges);
    }

    #[test]
    fn a_misspelled_provider_says_what_the_legal_values_are() {
        // Why IngressDecl deserializes by hand: `#[serde(untagged)]` reports
        // only "data did not match any variant of untagged enum IngressDecl",
        // which names neither the field nor the vocabulary. A config value that
        // fails to say what is wrong with it is the same class of defect W305
        // is about.
        let err = toml::from_str::<MirrorConfig>(
            "schema_version = 1\nshape = \"single-machine\"\n\
             [[ingress]]\nprovider = \"passwya\"\n",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("passwya"), "names the bad value: {msg}");
        assert!(msg.contains("passway"), "names the legal ones: {msg}");

        // Same for the scalar spelling.
        let err = toml::from_str::<MirrorConfig>(
            "schema_version = 1\nshape = \"single-machine\"\ningress = \"pasway\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("pasway"), "got: {err}");
    }

    // ── collation: what each NODE runs (W305 F2) ──

    fn planned(service: &str, plan: IngressPlan) -> PlannedEdge {
        PlannedEdge {
            service: service.into(),
            env: "cloud".into(),
            plan,
        }
    }

    /// A one-rule plan for `hostname`, fronted on `machines`.
    fn plan(provider: IngressProvider, machines: &[&str], hostname: &str, port: u16) -> IngressPlan {
        IngressPlan {
            provider,
            rules: vec![IngressRule {
                hostname: hostname.into(),
                port,
                slot: "compute".into(),
                provider_id: None,
                machine: None,
                upstream_host: Some("100.64.0.5".into()),
            }],
            front_doors: machines.iter().map(|s| s.to_string()).collect(),
            tunnel_id: None,
        }
    }

    #[test]
    fn two_services_fronting_one_node_collate_into_one_appliance() {
        // The fact no per-service apply can see: us-east-001 runs ONE passway,
        // and its upstream set is the union of every service pointed at it.
        let c = collate_front_doors(&[
            planned(
                "yah-marketing",
                plan(IngressProvider::Passway, &["us-east-001"], "yah.dev", 8080),
            ),
            planned(
                "yah-issues",
                plan(
                    IngressProvider::Passway,
                    &["us-east-001"],
                    "issues.yah.dev",
                    8731,
                ),
            ),
        ])
        .unwrap();

        assert_eq!(c.front_doors.len(), 1, "one appliance, not one per service");
        let door = &c.front_doors[0];
        assert_eq!(door.machine, "us-east-001");
        assert_eq!(
            door.passway_upstreams().unwrap(),
            vec!["issues.yah.dev=100.64.0.5:8731", "yah.dev=100.64.0.5:8080"]
        );
        assert_eq!(
            door.sources,
            vec!["yah-issues/cloud".to_string(), "yah-marketing/cloud".to_string()],
            "provenance answers `why is this hostname on this box`"
        );
        assert!(c.unplaced.is_empty());
    }

    #[test]
    fn one_service_across_three_origins_collates_to_three_appliances() {
        let c = collate_front_doors(&[planned(
            "yah-marketing",
            plan(
                IngressProvider::Passway,
                &["us-east-001", "us-south-001", "us-west-001"],
                "yah.dev",
                8080,
            ),
        )])
        .unwrap();
        assert_eq!(c.front_doors.len(), 3);
        // Every origin serves the identical set — N front doors, ONE deployment.
        for door in &c.front_doors {
            assert_eq!(
                door.passway_upstreams().unwrap(),
                vec!["yah.dev=100.64.0.5:8080"]
            );
        }
    }

    #[test]
    fn two_cohorts_on_one_node_are_two_connectors_not_a_conflict() {
        // W267 Gap 3's actual case, and the reason `tunnel_id` is in the
        // grouping key: one box, two orange networks, two cloudflared processes.
        let mut a = plan(
            IngressProvider::CloudflareTunnel,
            &["us-east-001"],
            "a.yah.dev",
            8080,
        );
        a.tunnel_id = Some("cohort-a".into());
        let mut b = plan(
            IngressProvider::CloudflareTunnel,
            &["us-east-001"],
            "b.yah.dev",
            8081,
        );
        b.tunnel_id = Some("cohort-b".into());

        let c = collate_front_doors(&[planned("svc-a", a), planned("svc-b", b)]).unwrap();
        assert_eq!(c.front_doors.len(), 2);
        assert_eq!(
            c.front_doors
                .iter()
                .map(|d| d.tunnel_id.clone())
                .collect::<Vec<_>>(),
            vec![Some("cohort-a".into()), Some("cohort-b".into())]
        );
    }

    #[test]
    fn one_hostname_through_two_providers_is_a_conflict_naming_both_services() {
        let err = collate_front_doors(&[
            planned(
                "yah-marketing",
                plan(IngressProvider::Passway, &["us-east-001"], "yah.dev", 8080),
            ),
            planned(
                "yah-legacy",
                plan(
                    IngressProvider::CloudflareTunnel,
                    &["us-west-001"],
                    "yah.dev",
                    8080,
                ),
            ),
        ])
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("two different providers"), "got: {msg}");
        assert!(msg.contains("yah-marketing/cloud"), "got: {msg}");
        assert!(msg.contains("yah-legacy/cloud"), "got: {msg}");
    }

    #[test]
    fn one_hostname_at_two_upstreams_is_a_conflict() {
        // Apply order would decide which one the box ends up with.
        let err = collate_front_doors(&[
            planned(
                "svc-a",
                plan(IngressProvider::Passway, &["us-east-001"], "yah.dev", 8080),
            ),
            planned(
                "svc-b",
                plan(IngressProvider::Passway, &["us-east-001"], "yah.dev", 9090),
            ),
        ])
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("two different upstreams"),
            "got: {err:#}"
        );
    }

    #[test]
    fn an_edge_with_nowhere_to_run_is_reported_not_dropped() {
        let c = collate_front_doors(&[planned(
            "yah-marketing",
            plan(IngressProvider::Passway, &[], "yah.dev", 8080),
        )])
        .unwrap();
        assert!(c.front_doors.is_empty());
        assert_eq!(c.unplaced, vec!["yah-marketing/cloud".to_string()]);
    }

    // ── the swap the seam exists for ──

    #[test]
    fn same_mirror_plans_identical_rules_under_either_provider() {
        let slots = "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n";
        let tunnel = only_plan(&mirror(IngressProvider::CloudflareTunnel, slots));
        let passway = only_plan(&mirror(IngressProvider::Passway, slots));
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
        let plan = only_plan(&m);
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
        let mut plan = only_plan(&m);
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
        let mut plan = only_plan(&m);
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
        let mut plan = only_plan(&m);
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
