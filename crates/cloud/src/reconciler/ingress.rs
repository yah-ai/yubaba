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
//! slots with `zone` + (`port` | `fronted`)  ─by edge selector─►  IngressPlan { provider, rules, front_doors }
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
//!
//! @yah:relay(R845, "Tunnel ingress cannot resolve Cloudflare creds for a static-machine compute slot")
//! @yah:status(review)
//! @yah:at(2026-09-02T07:05:16Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:gotcha("Reported by the noisetable camp (its R131-T6, the first tenant to declare ingress = cloudflare-tunnel). IngressPlan::provider_id() is the `use` of the first FRONTED slot that names one, and apply's CloudflareTunnel arm resolves the Cloudflare account id + API token through it (app/yah/cli/src/cloud.rs, then publish_tunnel_ingress -> CfProvider::resolve).")
//! @yah:gotcha("A slot is FRONTED when it declares `port`. So the field that says what runs the compute is also the field that says whose Cloudflare account holds the tunnel. For a compute slot on a borrowed bare box the compute provider is the inline kind = static (placement-only, no credentials), and there is then no way to name a Cloudflare provider at all: apply bails with 'no fronted slot declares use = <provider-id>'.")
//! @yah:gotcha("The workaround is to write use = cloudflare on the compute slot, which satisfies the lookup by lying about what runs the compute. noisetable deliberately did NOT do that; its mirror (.yah/services/noisetable-api/mirrors/cloud.toml in that camp) documents the gap instead and its front door cannot be applied until this is fixed.")
//! @yah:next("Proposed shape, mirroring what the edge already does for tunnel_id: give IngressEdge its own provider id field, so the front door names the account that holds its tunnel and the fronted slot keeps naming what runs the compute. W267 Gap 3 already argued this exact split for tunnel_id (which cohort a service fronts through is a property of the SERVICE, not of the box); credentials are the same kind of fact.")
//! @yah:next("Keep provider_id() as the fallback so every mirror on disk today (yah-marketing's bundle slot, use = cloudflare) is unchanged.")
//! @yah:next("Whatever lands, the bail message should name the fix. Today it says the fronted slot must declare use = <provider-id>, which for a static-machine slot is advice that cannot be followed.")
//! @yah:handoff("SHIPPED the edge-side split. [[ingress]] entries now take their own use = <provider-id> (IngressEdge.provider_id, serde-renamed to `use` so it is spelled exactly as a slot's). plan_ingress carries it onto IngressPlan.edge_provider_id; IngressPlan::provider_id() resolves edge-first and falls back to the first fronted slot's `use`, which is the pre-R845 rule, so every mirror on disk plans identically.")
//! @yah:handoff("DISCOVERED AND FIXED, beyond the ticket: the pre-R845 fallback picks the first rule with any `use`, sorted by hostname, so a mirror whose compute slot is use = hetzner could hand a Hetzner provider id to CfProvider::resolve. app/yah/cli/src/cloud.rs now prefers a fronted slot referencing a Cloudflare-KIND provider (cfg.provider(id).kind == Provider::Cloudflare) before falling back to plan.provider_id(); the pure planner cannot make that call, having no view of .yah/infra/providers/.")
//! @yah:handoff("An edge's `use` is now cross-ref validated like a slot's: CloudConfig::cross_ref_validate bails with ingress[N].use = <id> - no such provider, via a new MirrorConfig::ingress_edge_slice() that reads the [[ingress]] tables raw (ingress_edges() hard-fails on unrelated shape errors, wrong for a whole-workspace walk). A typo used to survive to the Cloudflare arm of apply.")
//! @yah:handoff("Bail message rewritten to name a followable fix: add use to the [[ingress]] edge, why the slot's `use` is only a fallback, and - for the scalar ingress = cloudflare-tunnel spelling, which has no edge table - convert to the list form. W267 Gap 3 gained a paragraph recording the split (docs are canon; the constraint now lives beside the tunnel_id argument it mirrors).")
//! @yah:verify("cargo test -p yah-cloud --lib (oss/yubaba): 949 passed, 0 failed - includes 4 new ingress tests (edge use overrides the slot's; a kind = static compute slot plans with no slot `use` at all; no-edge-use still answers off the slot; `use` round-trips through mirror TOML) and 1 new cross-ref test.")
//! @yah:verify("cargo check -p yah -p xtask --all-targets: clean. cargo test -p xtask --test main mirror_ingress: 6 passed - that one plans this camp's real .yah/services mirrors, so yah-marketing's bundle slot (use = cloudflare, no edge use) is proven unchanged.")
//! @yah:verify("cargo run -p xtask -- emit-schemas regenerated .yah/schema/mirror.toml.schema.json (new `use` on the edge). It also regenerated machine.toml.schema.json - a pre-existing doc-comment drift on the non-voter role variant, not mine; left in so the gate can go green. NOTE check-schema-drift.sh compares against git HEAD, so it reads red until these are committed.")
//! @yah:gotcha("The noisetable camp's mirror still needs the one-line edit on their side: add use = \"cloudflare\" to its [[ingress]] entry (or convert its scalar ingress = \"cloudflare-tunnel\" to the list form and put it there). Nothing in this camp's tree declares an edge `use` yet, so the new field is exercised only by unit tests until they apply.")
//! @yah:handoff("Installed: cargo xtask install -> ~/.local/bin/yah, sha256 1cac1e97b0651c731d6ce6180c51d80116071126a1f00f6e43a487bf836e8277, build id yah 0.8.29+6c8b994f-dirty, PATH resolves there. Confirmed by content, not mtime: strings -a on the installed binary finds the new bail text (`convert to the list form`, `nothing names the Cloudflare account`). MCP tool surface unchanged, so the app-bundle install is not needed.")
//! @yah:verify("strings -a ~/.local/bin/yah | grep -c 'convert to the list form' -> 1 (the installed CLI is the fixed one).")

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use tracing::{debug, info};

use crate::config::{resolve_machines_among, IngressEdge, IngressProvider};
use crate::{CloudflareClient, MachineConfig, MirrorConfig};

/// Slot field naming the public hostname a slot is fronted at.
const ZONE_FIELD: &str = "zone";
/// Slot field pinning the node-local port the front door dials. Already
/// `BundleSlot.port`'s meaning — the port kamaji binds the workload to and the
/// port the front door dials are the same port, so this reuses that field
/// rather than minting a parallel one.
///
/// **A value, no longer the opt-in** (R844-F5). It used to be both, which meant
/// deleting the key did not remove a pin — it removed the *slot* from the plan,
/// silently un-publishing a live hostname. [`FRONTED_FIELD`] now carries the
/// participation half, and this one is optional: a rule that declares no port
/// gets it from the fronting node's `GET /service-records?ready=true` via
/// [`IngressPlan::resolve_ports`], where `resolved_ports` reports what the
/// supervisor actually bound (R844-F2) rather than what a mirror asked for.
///
/// Declaring it still implies participation, so every mirror on disk plans
/// byte-identically across that change — and an explicit pin always wins over
/// discovery, exactly as [`UPSTREAM_HOST_FIELD`] does.
const PORT_FIELD: &str = "port";
/// Slot field that opts a slot into the front door and says nothing else:
/// `fronted = true` means "publish me", with the port left to discovery.
///
/// Its own field rather than a reuse of `zone`, because `zone` is overloaded: a
/// CDN-published static slot carries it meaning the *Cloudflare zone*. Keying
/// participation off `zone` would drag every such slot into the ingress plan
/// and fail the apply of mirrors that have no front door at all. Nor can the
/// `[[ingress]]` edge selector serve — every mirror on disk uses the scalar
/// spelling, which yields one selectorless edge that claims everything, so it
/// would drag in exactly the same static slots. The signal has to be slot-side
/// and mean one thing.
///
/// `fronted = false` is not an opt-*out* of a declared `port`: a slot with a
/// port is fronted regardless, which keeps the one silent-de-listing shape this
/// field exists to remove from reappearing under a new spelling.
const FRONTED_FIELD: &str = "fronted";
/// Slot field naming the machine the fronted workload runs on.
const MACHINE_FIELD: &str = "machine";
/// Plural spelling of [`MACHINE_FIELD`], used by placement-list slots such as
/// `[providers.bundle]`. Read as a fallback so a bundle tier is plannable at
/// all — before this, `machines = ["us-east-001"]` was invisible to the planner
/// and every rule derived from a bundle slot resolved no upstream.
///
/// **Read whole** (R844-F3). It used to contribute only its first entry, on the
/// premise that a workload placed on several nodes still answers on any one of
/// them — which R844-F4 disproved by measurement: the service-record store is
/// node-local (a `watch` + a per-node JSON ledger, replicated nowhere), so node
/// A's answer covers node A's workloads and no others. Discarding the rest of
/// the list therefore aimed discovery at a strict subset of the declared
/// placement and rendered a strict subset of the backends — a front door that
/// looks like it worked. The whole list now lands in
/// [`IngressRule::machines`], the fanout asks every entry
/// ([`IngressPlan::workload_machines`]) and the renderer carries every answer
/// ([`IngressRule::upstream_hosts`]).
///
/// Front-door placement remains a different question with its own field —
/// `MirrorConfig::ingress_machines`. Widening the workload's placement set must
/// never be read as deploying a second copy of the workload; it says where the
/// already-declared copies are, so that discovery can find all of them.
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
    /// Node-local port the fronted workload listens on — `None` until
    /// [`IngressPlan::resolve_ports`] fills it, for a slot that declared
    /// `fronted = true` without pinning a number.
    ///
    /// Optional for the same reason [`upstream_hosts`](Self::upstream_hosts) is
    /// resolved rather than defaulted (R844-F5): once kamaji allocates the port
    /// (`PortAllocator::resolve`), the number the workload actually bound is
    /// unknowable from the mirror, so a rule that carried a `u16` could only
    /// carry a *declaration* — and the front door dialing a declared number
    /// while the supervisor bound another one fails at request time, long after
    /// the apply that looked clean. A declared `port` still wins; discovery
    /// only answers where the mirror stayed silent.
    pub port: Option<u16>,
    /// Mirror provider slot this rule was derived from (`"compute"`, …). Kept
    /// so an error or a summary line can name the slot the operator wrote.
    pub slot: String,
    /// The slot's `use = "<provider-id>"`, when it references an infra-declared
    /// provider. The cloudflare-tunnel arm resolves its account id + API token
    /// through this, exactly as the R2 custom-domain reconciler does.
    pub provider_id: Option<String>,
    /// Every node the fronted **workload** is placed on, in declaration order:
    /// the slot's `machine = "<name>"` (one entry), its `machines = [...]` list
    /// (all of them), or the constraint-resolved placement
    /// [`resolve_ingress_placements`] hands in. Empty when the slot declares no
    /// placement at all.
    ///
    /// A set, not an option (R844-F3). One entry is the common case and stays
    /// exact; a workload at horizontal scale > 1 is a set, and the two facts
    /// this drives — which nodes the discovery fanout must ask, and which node's
    /// `MachineConfig.cloudflared` tunnel the rules publish to — are both
    /// wrong when the set is silently truncated to its first element.
    pub machines: Vec<String>,
    /// Every address the front door dials this workload at — one per live
    /// backend. Empty until [`IngressPlan::resolve_upstreams`] (or
    /// [`resolve_upstreams_from`](IngressPlan::resolve_upstreams_from)) runs, or
    /// a single pinned entry when the slot declares `upstream_host`.
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
    ///
    /// **Plural because the fan-out is real** (R844-F3): a workload on N nodes
    /// has N mesh IPs, and passway's `PASSWAY_UPSTREAMS` grammar already load
    /// balances several entries sharing a hostname (`parse_upstream_sets` pushes
    /// into one set per host key). Collapsing to one here would publish one
    /// backend out of N while every line in the mirror still read correctly.
    pub upstream_hosts: Vec<String>,
}

impl IngressRule {
    /// Every `host:port` the front door dials, once resolved — one per backend,
    /// in resolution order.
    ///
    /// Erroring on empty rather than returning an empty vec is the point: a
    /// front door that publishes a hostname with no backend advertises a 502,
    /// which is worse than a failed apply.
    ///
    /// **The single place an undialable rule is reported** (R844-F5). A rule
    /// needs two resolved halves — a port and at least one address — and both
    /// come from the same discovery read, so a rule missing both says so in one
    /// message here rather than failing twice in two different words.
    pub fn upstreams(&self) -> Result<Vec<String>> {
        let (Some(port), false) = (self.port, self.upstream_hosts.is_empty()) else {
            let mut missing: Vec<String> = Vec::new();
            if self.port.is_none() {
                missing.push(format!(
                    "no resolved port: the slot declares `{FRONTED_FIELD} = true` without \
                     `{PORT_FIELD}`, so the number has to come from the node's `resolved_ports` \
                     (R844-F2) and no ready record supplied one"
                ));
            }
            if self.upstream_hosts.is_empty() {
                missing.push(format!(
                    "no resolved upstream address: the workload's mesh IP is allocated at \
                     deploy time (R599-F12), so it cannot come from the mirror"
                ));
            }
            return Err(anyhow::anyhow!(
                "slot [providers.{}] fronted at {} cannot be dialed — {}. Either the fronting \
                 node's `GET /service-records?ready=true` must report a ready record for it, or \
                 the slot must pin `{PORT_FIELD} = <n>` / `{UPSTREAM_HOST_FIELD} = \"<addr>\"` \
                 explicitly.",
                self.slot,
                self.hostname,
                missing.join("; ")
            ));
        };
        Ok(self
            .upstream_hosts
            .iter()
            .map(|host| format!("{host}:{port}"))
            .collect())
    }

    /// Every backend as a **displayable** `host:port`, resolved halves shown and
    /// unresolved ones spelled `<unresolved>` — never an error (R844-T10).
    ///
    /// The read-only counterpart of [`upstreams`](Self::upstreams), for a
    /// renderer whose job is to describe the plan rather than to act on it:
    /// `yah cloud ingress collate` and `yah cloud validate`. Those make no
    /// network call by design, so a rule taking its port from the supervisor
    /// (`fronted = true`, no `port`) is *expected* to be half-resolved there and
    /// reporting it as a failure would train an operator to ignore the output.
    ///
    /// It shows **each half independently**, which is the whole point. The
    /// previous rendering collapsed any error to `<unresolved>:<port_label>` and
    /// so threw away a known address — after R844-F12 the host resolves offline
    /// from the placement machine's declared `mesh_ipv4`, so a portless apex now
    /// reads `100.64.0.3:<unresolved>` and names exactly the one fact that is
    /// genuinely runtime, instead of claiming ignorance of both.
    ///
    /// **Not evidence the front door works.** Nothing here is a measurement:
    /// the address comes from a mirror or a machine toml, so a rule can render
    /// perfectly and still dial nothing. That distinction has cost this camp a
    /// 19-day outage once already, via a pinned `upstream_host` left at
    /// `127.0.0.1` that every collation printed back confidently.
    pub fn upstream_labels(&self) -> Vec<String> {
        let port = self.port_label();
        if self.upstream_hosts.is_empty() {
            return vec![format!("<unresolved>:{port}")];
        }
        self.upstream_hosts
            .iter()
            .map(|host| format!("{host}:{port}"))
            .collect()
    }

    /// This rule's port for a message — the number, or `<unresolved>` before
    /// [`IngressPlan::resolve_ports`] has answered for it.
    ///
    /// Exists so every diagnostic renders an unresolved port the same way. A
    /// call site formatting `Option<u16>` directly prints `None`, which reads
    /// as a bug in the tool rather than a fact about the fleet.
    pub fn port_label(&self) -> String {
        self.port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "<unresolved>".to_string())
    }

    /// The **first** `host:port`, for a renderer that can carry only one backend
    /// per hostname.
    ///
    /// Not a deprecated spelling of [`upstreams`](Self::upstreams): cloudflared's
    /// ingress grammar takes exactly one `service` per hostname rule, and its
    /// high availability comes from running several *connectors* into the tunnel,
    /// not from listing several services. So the tunnel arm genuinely collapses
    /// the set, and does it here in one named place rather than by indexing
    /// `[0]` at each call site.
    pub fn upstream(&self) -> Result<String> {
        Ok(self
            .upstreams()?
            .into_iter()
            .next()
            .expect("upstreams() errors rather than returning empty"))
    }

    /// cloudflared ingress-rule `service` target — the first backend, per
    /// [`upstream`](Self::upstream).
    pub fn service_url(&self) -> Result<String> {
        Ok(format!("http://{}", self.upstream()?))
    }

    /// This rule's `PASSWAY_UPSTREAMS` entries in the R594-F10 host-prefixed
    /// form — **one per backend**, all sharing the hostname.
    ///
    /// Repeating a hostname is the grammar's own load-balancing spelling, not an
    /// abuse of it: passway's `parse_upstream_sets` collects entries into a
    /// `BTreeMap<HostKey, Vec<SocketAddr>>` and builds one load balancer per
    /// host key. Emitting a single entry for a workload on N nodes would send
    /// every request to one of them.
    pub fn passway_upstreams(&self) -> Result<Vec<String>> {
        Ok(self
            .upstreams()?
            .into_iter()
            .map(|addr| format!("{}={addr}", self.hostname))
            .collect())
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
    /// fronted slots name machines: it falls back to the union of their
    /// placements, which is the co-located shape every mirror had before this
    /// field existed, widened to every node the workload runs on (R844-F3). It
    /// **is** empty when neither is declared, and each provider arm decides
    /// whether that is an error (the tunnel arm) or a placeholder (passway's
    /// rendered deploy line).
    ///
    /// Independent of [`IngressRule::machines`] by design, even though the
    /// fallback is derived from it: this is where the *front door* runs, that is
    /// where the *workload* runs. Declaring `ingress_machines` fixes this list
    /// and the workload's placement has no further say — which is what lets the
    /// ingress tier be wider (or narrower) than the service tier.
    pub front_doors: Vec<String>,
    /// Cloudflare Tunnel id this edge declared, overriding the fronting
    /// machine's own (W267 Gap 3). `None` means "use the node's" — the common
    /// case, and the only shape that existed before W305 F2.
    pub tunnel_id: Option<String>,
    /// Provider id this edge declared its credentials under (`use = "…"` on the
    /// `[[ingress]]` entry). `None` means "read it off the fronted slot" — the
    /// only shape that existed before R845.
    ///
    /// Kept raw beside the resolved [`provider_id`](Self::provider_id) accessor
    /// on purpose: an apply that wants to prefer a *Cloudflare-kind* slot over
    /// whichever slot happened to sort first can only do that if it can tell an
    /// explicit declaration from a derived one.
    pub edge_provider_id: Option<String>,
}

impl IngressPlan {
    /// Every rule rendered as a `PASSWAY_UPSTREAMS` entry, ready to hand to
    /// `PasswayIngressSpec::upstreams`.
    pub fn passway_upstreams(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for rule in &self.rules {
            out.extend(rule.passway_upstreams()?);
        }
        Ok(out)
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
    /// `discover` answers with **every** address serving the rule, not the first
    /// one: a workload at horizontal scale > 1 has one per node it runs on, and
    /// the renderer carries the whole set (R844-F3). An empty vec means the
    /// control plane answered and has no ready record.
    pub fn resolve_upstreams<F>(&mut self, mut discover: F) -> Result<()>
    where
        F: FnMut(&IngressRule) -> Result<Vec<String>>,
    {
        for rule in &mut self.rules {
            if !rule.upstream_hosts.is_empty() {
                continue;
            }
            rule.upstream_hosts = discover(rule)?;
            // Surface the failure with the rule's own context.
            rule.upstreams()?;
        }
        Ok(())
    }

    /// Fill in the node-local port each rule's front door dials.
    ///
    /// The port half of [`resolve_upstreams`](Self::resolve_upstreams), and the
    /// step that lets a mirror say `fronted = true` without pinning a number
    /// (R844-F5). `discover` is backed by the fronting node's
    /// `GET /service-records?ready=true`, whose `resolved_ports` is what the
    /// supervisor **bound** rather than what a mirror asked for — the only
    /// source that stays correct once kamaji allocates the port.
    ///
    /// A rule that declared `port` keeps it: an explicit operator pin always
    /// wins, exactly as `upstream_host` does, which is why every mirror on disk
    /// applies byte-identically across this change.
    ///
    /// **Call this before [`resolve_upstreams`](Self::resolve_upstreams)**, not
    /// after: discovery matches a record *by port*, so a rule whose port is
    /// still `None` cannot pick its address out of a node running several
    /// workloads.
    ///
    /// Leaving a rule unresolved is deliberately **not** an error here.
    /// [`IngressRule::upstreams`] is already the single place an undialable
    /// rule is reported, and a rule that resolved neither half should say that
    /// once rather than twice.
    ///
    /// Pure, like the planner it follows: the caller does the read and hands
    /// the answer in, so `plan_ingress` keeps taking no network and
    /// `xtask/tests/mirror_ingress.rs` keeps planning the real tree as a unit
    /// test. Third instance of that shape, after
    /// [`resolve_ingress_placements`] and
    /// [`resolve_upstreams`](Self::resolve_upstreams).
    pub fn resolve_ports<F>(&mut self, mut discover: F) -> Result<()>
    where
        F: FnMut(&IngressRule) -> Result<Option<u16>>,
    {
        for rule in &mut self.rules {
            if rule.port.is_some() {
                continue;
            }
            rule.port = discover(rule)?;
        }
        Ok(())
    }

    /// Fill in each rule's upstream address from its placement machines'
    /// **declared** mesh addresses — the offline half of upstream resolution
    /// (R844-F12).
    ///
    /// This is what lets a slot drop `upstream_host` without giving up offline
    /// planning. The pin was never a fact only the network knew: a rule's
    /// placement set is already machine *names*
    /// ([`IngressRule::machines`], R844-F3), and every machine's
    /// `[registration].mesh_ipv4` is right there in `.yah/infra/machines/`. So
    /// the pin was a hand-copy of a value the config already stated twice —
    /// `.yah/infra/machines/us-east-001.toml` says `mesh_ipv4 = "100.64.0.3"`
    /// and the apex mirror said `upstream_host = "100.64.0.3"` — with nothing
    /// keeping the two in step. The copy has drifted before: this mirror's pin
    /// was once found still naming `127.0.0.1` after a second front door
    /// existed, and every rendered rule looked correct.
    ///
    /// **Declared, not authoritative.** Run this only where there is no live
    /// read to have — `yah cloud ingress collate`, `yah cloud validate`, the
    /// `xtask` suite. The apply path resolves through
    /// [`resolve_upstreams_from`](Self::resolve_upstreams_from) instead, and
    /// must keep doing so: a service record reports the address the supervisor
    /// actually bound, while this reports what a TOML claims, and when they
    /// disagree the TOML is the one that can be stale. Calling this *before*
    /// discovery would silently make the stale value win, since every resolver
    /// here skips a rule that already has an address — the exact
    /// confidently-wrong shape R844 exists to remove. It is the offline
    /// renderer's answer, not a second source of truth.
    ///
    /// Pure: `mesh_addrs` is handed in as data by a caller that already loaded
    /// the machine tomls ([`machine_mesh_addrs`]), so `plan_ingress` and
    /// everything after it still take no network, no credentials and no
    /// `CloudConfig` — the property `xtask/tests/mirror_ingress.rs` depends on
    /// to plan the camp's real `.yah/services` tree as a unit test. Fourth
    /// instance of that shape, after [`resolve_ingress_placements`],
    /// [`resolve_upstreams`](Self::resolve_upstreams) and
    /// [`resolve_ports`](Self::resolve_ports).
    ///
    /// Silent where it cannot answer, like [`resolve_ports`](Self::resolve_ports):
    /// a machine with no declared `mesh_ipv4` contributes nothing and the rule
    /// stays empty, so [`IngressRule::upstreams`] remains the single place an
    /// undialable rule is reported. A rule that already has an address — a
    /// pinned `upstream_host`, or a discovery answer — is left alone.
    pub fn resolve_upstreams_from_config(&mut self, mesh_addrs: &HashMap<String, String>) {
        for rule in &mut self.rules {
            if !rule.upstream_hosts.is_empty() {
                continue;
            }
            // Declaration order, matching `machines` — the renderer emits one
            // `PASSWAY_UPSTREAMS` entry per backend and a reordered set would
            // look like drift on every apply.
            rule.upstream_hosts = rule
                .machines
                .iter()
                .filter_map(|name| mesh_addrs.get(name).cloned())
                .collect();
        }
    }

    /// Provider id the front door's credentials resolve through — the edge's
    /// own `use`, falling back to the `use` of the first fronted slot that
    /// names one.
    ///
    /// The fallback is why every mirror on disk before R845 keeps working: it
    /// *is* the pre-R845 rule. It is only a fallback, though, because the two
    /// answers are different facts — the slot's `use` says what runs the
    /// compute, the edge's says whose account holds the tunnel — and they
    /// coincide only when the same vendor does both.
    ///
    /// Unlike [`tunnel_id`](Self::tunnel_id), whose fallback (the node's
    /// `MachineConfig.cloudflared`) lives in a config tree this pure planner
    /// deliberately cannot see, this one resolves here: both candidates are
    /// already in the plan.
    pub fn provider_id(&self) -> Option<&str> {
        self.edge_provider_id
            .as_deref()
            .or_else(|| self.slot_provider_ids().next())
    }

    /// Every provider id the fronted slots name, in rule order.
    ///
    /// The apply layer uses this to pick the slot that references a
    /// *Cloudflare-kind* provider rather than whichever slot sorted first —
    /// a distinction [`provider_id`](Self::provider_id) cannot make, because a
    /// pure planner has no view of `.yah/infra/providers/`.
    pub fn slot_provider_ids(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().filter_map(|r| r.provider_id.as_deref())
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
///
/// **Set-valued, and resolving to as many as the constraint declares
/// (R844-F8).** The return type is a placement *set* per role because that is
/// what [`IngressRule::machines`] carries and what the discovery fanout asks.
/// A `required` block with no `replicas` still resolves to exactly one machine
/// — every mirror on disk is that shape, and they all resolve byte-identically
/// — while `replicas = N` resolves to the first N machines the constraint
/// matches.
///
/// **The count is declared, never inferred from the match count.** A constraint
/// matching four nodes and asking for two places on two; otherwise adding a box
/// to the fleet would silently scale a production front door.
///
/// The reason R844-F3 stopped at one, and the invariant that replaces it: this
/// and the deploy-side resolver
/// ([`resolve_bundle_machines`](super::mesofact_bundle::resolve_bundle_machines))
/// must agree **set for set**, not merely in count, or the planner aims
/// discovery at nodes nothing was ever deployed to and the front door renders a
/// *subset* of the backends — the failure that looks like it worked. They now
/// agree by construction rather than by test: both bottom out in the same
/// `select_matching` over the same declaration-ordered `cfg.machines` slice
/// (here via [`resolve_machines_among`], there via `CloudConfig::resolve_machines`).
///
/// A slot declaring a literal `machines = [a, b]` is still untouched by this
/// and read whole by [`plan_ingress`] — that remains the imperative spelling of
/// horizontal scale, beside the derived one.
pub fn resolve_ingress_placements(
    machines: &[MachineConfig],
    mirror: &MirrorConfig,
) -> Result<HashMap<String, Vec<String>>> {
    let mut placements = HashMap::new();
    for (role, slot) in &mirror.providers {
        let fields = slot.fields();
        if fields.contains_key(MACHINE_FIELD) || fields.contains_key(MACHINES_FIELD) {
            continue;
        }
        let Some(required) = slot.required() else {
            continue;
        };
        let resolved = resolve_machines_among(machines, &required).with_context(|| {
            format!("resolving placement for [providers.{role}] required = {{ … }}")
        })?;
        placements.insert(
            role.clone(),
            resolved.iter().map(|m| m.name.clone()).collect(),
        );
    }
    Ok(placements)
}

/// Every machine's declared mesh address, keyed by machine name (R844-F12).
///
/// The data half of [`IngressPlan::resolve_upstreams_from_config`], split out
/// for the same reason [`resolve_ingress_placements`] is: the planner stays
/// pure and the caller — which has already loaded `.yah/infra/machines/` for
/// placement resolution — does the reading. No new input, just a second lookup
/// over a slice that is already in hand.
///
/// Reads through [`MachineConfig::mesh_ipv4`], so it picks up the same
/// `[registration].mesh_ipv4`-then-legacy-`yubaba_url`-host precedence every
/// other consumer sees; a machine that declares neither is simply absent, and
/// a rule placed only on such machines resolves no address offline. That is
/// the honest answer — silence, reported once by
/// [`IngressRule::upstreams`] — rather than a guess.
pub fn machine_mesh_addrs(machines: &[MachineConfig]) -> HashMap<String, String> {
    machines
        .iter()
        .filter_map(|m| Some((m.name.clone(), m.mesh_ipv4()?.to_string())))
        .collect()
}

/// Derive every declared edge's rules from the mirror's provider slots.
///
/// A slot participates when it declares `fronted = true` **or** a `port`; its
/// `zone` is the public hostname it is fanned in at. Participation without a
/// `zone` is an **error**, not a skip — a mirror that declares a front door and
/// a fronted slot but no hostname is always a typo, and silently dropping it is
/// exactly the failure mode where an operator flips
/// `ingress = "cloudflare-tunnel"` and gets a front door that publishes
/// nothing. A slot with `zone` and neither signal is skipped: that is a
/// CDN-published tier, not a fronted one.
///
/// The two signals are separate as of R844-F5. `port` used to be both the value
/// and the opt-in, so deleting it did not un-pin a port, it removed the slot
/// from the plan — a live hostname silently losing its backend. `port` still
/// implies participation (nothing on disk changes), but a slot may now opt in
/// with `fronted = true` alone and take its port from
/// [`IngressPlan::resolve_ports`].
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
///
/// @yah:ticket(R844-F12, "Derive a rule's upstream host from the placement machine's declared mesh_ipv4 — retire upstream_host without giving up offline planning")
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:at(2026-09-03T22:18:35Z)
/// @yah:parent(R844)
/// @yah:next("THE SHAPE: when a slot declares no `upstream_host`, fall back to the DECLARED mesh address of each machine in the rule's resolved placement set, instead of leaving upstream_hosts empty for discovery to fill. IngressRule.machines is already the placement set (R844-F3) and `resolve_ingress_placements(machines: &[MachineConfig], mirror)` at ingress.rs:515 already receives every MachineConfig, so the data is in hand at plan time — this is a lookup, not a new input, and plan_ingress keeps taking no network and no CloudConfig. Live discovery via IngressPlan::resolve_upstreams should still WIN when it answers, because it reports what is actually bound; the config fallback is what makes the plan renderable offline rather than what makes it authoritative.")
/// @yah:verify("EQUIVALENCE IS THE TEST, NOT NON-EMPTINESS. With `upstream_host` deleted from .yah/services/yah-marketing/mirrors/cloud.toml, `yah cloud ingress collate` must still render `yah.dev -> 100.64.0.3:8080` on BOTH front doors (us-east-001 and us-south-001), byte-identical to the pinned output, and `cargo test -p xtask --test main mirror_ingress` must be green WITHOUT network. A partial or empty answer that renders a SUBSET of backends looks exactly like success — that is the failure class R844 exists to eliminate and the reason R772 reverted this same deletion once.")
/// @yah:gotcha("WHY THIS IS SAFE AND WHERE ITS LIMIT IS. Safe: .yah/infra/machines/us-east-001.toml:109 declares mesh_ipv4 = \"100.64.0.3\", the apex's live service record reports endpoints [\"100.64.0.3:8080\"], and the two agree — verified against the live fleet 2026-09-03. The existing xtask assertion the_apex_bundle_places_on_the_node_set_its_upstreams_are_pinned_to already performs exactly this offline lookup (its failure message reads \"us-east-001 resolves to mesh address 100.64.0.3\"), so the derivation is proven to work; it is simply not wired into planning. THE LIMIT: R599-F12's doc says native_bind_ip binds the workload's ALLOCATED MeshAssignment, not flatly the node's IP. Those coincide for the apex today, but R844-B11 reports container records advertising a COUNTER-ALLOCATED mesh IP that collides with real node addresses — so this fallback is sound for node-bound NATIVE workloads and its general validity depends on how B11 resolves. Hence depends_on(R844-B11): either land B11 first, or scope the fallback explicitly to the native shape and make it refuse rather than guess for containers.")
/// @yah:depends_on(R844-B11)
/// @yah:handoff("SHIPPED, AND THE PIN IS NOW REDUNDANT RATHER THAN LOAD-BEARING. Two additions to oss/yubaba/crates/cloud/src/reconciler/ingress.rs: `machine_mesh_addrs(&[MachineConfig]) -> HashMap<String,String>` (machine name -> declared `[registration].mesh_ipv4`, read through `MachineConfig::mesh_ipv4()` so it inherits the same registration-then-legacy-url precedence every other consumer sees), and `IngressPlan::resolve_upstreams_from_config(&mesh_addrs)`, which fills each rule's `upstream_hosts` from its placement set in declaration order. Wired into `collate_workspace_ingress` (validate.rs) — the ONE seam, which is why both `yah cloud ingress collate` AND `yah cloud validate` get it, since both call that function (app/yah/cli/src/cloud.rs:3709 and :7521). Exported via reconciler/mod.rs.")
/// @yah:verify("EQUIVALENCE, NOT NON-EMPTINESS, AND AGAINST THE REAL FILE. New `xtask/tests/mirror_ingress.rs::the_apex_renders_the_same_backends_with_upstream_host_deleted` reads .yah/services/yah-marketing/mirrors/cloud.toml OFF DISK, strips the `upstream_host` line from the text, and asserts the pinless render equals the pinned render exactly — `[\"yah.dev=100.64.0.3:8080\"]` both ways. It also asserts the strip actually happened (so a rename cannot make it compare the pinned mirror to itself and pass forever) and that the pinless plan resolves NOTHING before the config pass runs, so the equality provably comes from the derivation and not from some other path supplying the address. cargo test -p xtask --test main mirror_ingress = 11 passed / 0 failed, still with no network, no credentials and no CloudConfig — the purity canary holds.")
/// @yah:verify("Five new unit tests in ingress.rs pin the semantics the xtask test cannot isolate: a pinless slot derives its address; every placement machine contributes a backend IN DECLARATION ORDER (a subset here is the failure that looks like it worked); a pinned `upstream_host` still wins; a machine with no declared mesh address resolves NOTHING rather than falling back to loopback or a neighbour; and a live discovery answer is not overwritten by the declaration. cargo test -p yah-cloud --lib = 997 passed / 0 failed / 4 ignored. cargo test -p yubaba --lib = 632 passed / 0 failed. cargo check -p yah -p xtask --all-targets = exit 0.")
/// @yah:handoff("THE PRECEDENCE IS THE SAFETY PROPERTY, AND IT IS ORDERING, NOT CODE. Config-derived is DECLARED, never authoritative: it runs ONLY where there is no live read to have (collate, validate, xtask). The apply path still resolves through `resolve_upstreams_from` and MUST keep doing so — a service record reports what the supervisor actually bound, this reports what a TOML claims, and when they disagree the TOML is the one that can be stale. Because every resolver here skips a rule that already has an address, calling the config pass BEFORE discovery would silently make the stale value win. That is the confidently-wrong shape R844 exists to remove, so it is asserted as a test (`a_live_answer_is_not_overwritten_by_the_declaration`) rather than left as a convention. The drift is not hypothetical: this mirror's pin was once found still naming 127.0.0.1 after a second front door existed, and every rendered rule looked correct.")
/// @yah:handoff("DEPENDS_ON(R844-B11) IS DISCHARGED, in B11's favour. This ticket's own gotcha said the derivation was \"sound for node-bound NATIVE workloads\" and that its general validity depended on how B11's container mesh-IP bug resolved. B11 (now at review, same session) deleted `alloc_mesh_ip` outright and routed the container tier through `ServerState::workload_bind_ip()` = the node's own mesh address — the same value `admit_bundle` already used. So BOTH tiers now advertise the answering node's own address, which is precisely the fact `.yah/infra/machines/<node>.toml` declares as `[registration].mesh_ipv4`. The two sources agree by construction rather than by coincidence, and this fallback needed no container-specific scoping or refusal.")
pub fn plan_ingress(
    mirror: &MirrorConfig,
    placements: &HashMap<String, Vec<String>>,
) -> Result<Vec<IngressPlan>> {
    let edges = declared(mirror)?;
    if edges.is_empty() {
        return Ok(Vec::new());
    }

    let mut rules = Vec::new();
    for (role, slot) in &mirror.providers {
        let fields = slot.fields();
        let declared_port = fields.get(PORT_FIELD).and_then(|v| v.as_integer());
        let fronted = match fields.get(FRONTED_FIELD) {
            None => false,
            Some(value) => value.as_bool().ok_or_else(|| {
                anyhow::anyhow!(
                    "slot [providers.{role}] {FRONTED_FIELD} = {value} is not a boolean — write \
                     `{FRONTED_FIELD} = true` to put the slot behind the front door. Any other \
                     spelling reads as `not fronted`, which would drop the slot from the plan \
                     silently."
                )
            })?,
        };
        // The opt-in, either spelling. `port` implies it so that every mirror
        // written before `fronted` existed plans identically (R844-F5).
        if declared_port.is_none() && !fronted {
            continue;
        }
        let Some(zone) = fields.get(ZONE_FIELD).and_then(|v| v.as_str()) else {
            let (declared, drop_field) = match declared_port {
                Some(p) => (format!("{PORT_FIELD} = {p}"), PORT_FIELD),
                None => (format!("{FRONTED_FIELD} = true"), FRONTED_FIELD),
            };
            bail!(
                "mirror declares {} ingress edge(s) and slot [providers.{role}] declares \
                 {declared}, but no `zone` — an ingress provider fans a public hostname in to a \
                 node-local port, so it has nothing to publish that slot at. Add \
                 `zone = \"<hostname>\"` to the slot, or drop `{drop_field}` if this slot is \
                 not fronted.",
                edges.len()
            );
        };
        let port = match declared_port {
            Some(p) => Some(u16::try_from(p).with_context(|| {
                format!("slot [providers.{role}] {PORT_FIELD} = {p} is not a valid TCP port")
            })?),
            // Filled by `IngressPlan::resolve_ports` from the node's service
            // records — the port the supervisor actually bound.
            None => None,
        };
        rules.push(IngressRule {
            hostname: zone.to_string(),
            port,
            slot: role.clone(),
            provider_id: slot.provider_id().map(str::to_string),
            machines: declared_machines(&fields)
                .unwrap_or_else(|| placements.get(role).cloned().unwrap_or_default()),
            upstream_hosts: fields
                .get(UPSTREAM_HOST_FIELD)
                .and_then(|v| v.as_str())
                .map(|h| vec![h.to_string()])
                .unwrap_or_default(),
        });
    }

    // Stable order: two applies of an unchanged mirror must produce identical
    // provider config, or every run looks like drift.
    rules.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    if rules.is_empty() {
        bail!(
            "mirror declares {} ingress edge(s) but no provider slot declares `{PORT_FIELD}` or \
             `{FRONTED_FIELD} = true` — there is nothing to publish. Either add `zone` plus one \
             of those to the slot the front door fronts (`{FRONTED_FIELD} = true` takes the port \
             from the node's service records; `{PORT_FIELD}` pins it), or remove the `ingress` \
             declaration.",
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

/// The placement a slot spells out literally, or `None` when it declares none
/// and a constraint has to answer instead.
///
/// `machine = "<name>"` wins over `machines = [...]` — the pre-existing
/// precedence, kept because the singular form is the narrower statement and an
/// operator who wrote both meant the specific one. The plural form is read
/// **whole**: see [`MACHINES_FIELD`] for why taking only its first entry was a
/// silent subset.
///
/// A declared-but-empty `machines = []` is `None`, not an empty set: it says
/// nothing about placement, so the constraint fallback should still get a turn
/// rather than the slot resolving to "placed nowhere".
fn declared_machines(fields: &std::collections::BTreeMap<String, toml::Value>) -> Option<Vec<String>> {
    if let Some(one) = fields.get(MACHINE_FIELD).and_then(|v| v.as_str()) {
        return Some(vec![one.to_string()]);
    }
    let list: Vec<String> = fields
        .get(MACHINES_FIELD)
        .and_then(|v| v.as_array())?
        .iter()
        .filter_map(|v| v.as_str())
        .map(str::to_string)
        .collect();
    (!list.is_empty()).then_some(list)
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
                "{}: fronts nothing. Its selector matches no slot that declares `zone` plus \
                 `{PORT_FIELD}` or `{FRONTED_FIELD} = true` — a typo'd slot name is otherwise \
                 invisible, because the front door still deploys and simply publishes an empty \
                 rule set.",
                edge.label()
            );
        }
        // Front-door placement: the edge's own list wins, and falls back to the
        // fronted workload's own nodes — the co-located shape, which stays the
        // default because it is what every mirror written before this field
        // meant.
        //
        // R844-F3: the fallback is the UNION of the fronted slots' placements,
        // not the first one that named a node. Co-location at horizontal scale
        // > 1 means one front door per node the workload runs on; picking the
        // first left the other nodes' copies with no door in front of them, so
        // scaling the workload silently did not scale the front door. This
        // widens the INGRESS tier only — nothing here deploys a workload, and
        // the set it unions over is the placement the mirror already declared.
        let front_doors = if edge.machines.is_empty() {
            let mut out: Vec<String> = Vec::new();
            for machine in rules.iter().flat_map(|r| r.machines.iter()) {
                if !out.contains(machine) {
                    out.push(machine.clone());
                }
            }
            out
        } else {
            edge.machines.clone()
        };
        plans.push(IngressPlan {
            provider: edge.provider,
            rules,
            front_doors,
            tunnel_id: edge.tunnel_id.clone(),
            edge_provider_id: edge.provider_id.clone(),
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
        let mut out = Vec::new();
        for rule in &self.rules {
            out.extend(rule.passway_upstreams()?);
        }
        Ok(out)
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
                    // The whole upstream SET is the compared value, not just its
                    // first entry: two services declaring the same hostname over
                    // overlapping-but-unequal backend sets is the same
                    // last-apply-wins hazard as two disjoint ones (R844-F3).
                    if (first_rule.port, &first_rule.upstream_hosts)
                        != (rule.port, &rule.upstream_hosts)
                    {
                        bail!(
                            "hostname {:?} is fronted at two different upstreams — {} \
                             (providers.{}, port {}) and {} (providers.{}, port {}). One front \
                             door publishes one rule per hostname, so whichever service applies \
                             last wins on the box.",
                            rule.hostname,
                            first_edge.label(),
                            first_rule.slot,
                            first_rule.port_label(),
                            edge.label(),
                            rule.slot,
                            rule.port_label()
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
            provider_id: None,
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
                    port: Some(9090),
                    slot: "receiver".into(),
                    provider_id: Some("cloudflare".into()),
                    machines: Vec::new(),
                    upstream_hosts: Vec::new(),
                },
                IngressRule {
                    hostname: "z.yah.dev".into(),
                    port: Some(8080),
                    slot: "compute".into(),
                    provider_id: Some("hetzner".into()),
                    machines: vec!["us-east-001".into()],
                    upstream_hosts: Vec::new(),
                },
            ]
        );
        // Credentials + placement are read off the slots, not asked for twice.
        assert_eq!(plan.provider_id(), Some("cloudflare"));
        assert_eq!(plan.workload_machines(), vec!["us-east-001"]);
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
        // node that actually holds the deployment — one node, not two, even
        // though the front door now spans two.
        assert_eq!(plan.workload_machines(), vec!["us-east-001"]);
    }

    #[test]
    fn a_bundle_slots_machines_list_is_read_whole_as_placement() {
        // `[providers.bundle]` spells placement `machines`, not `machine`.
        // Before R330-F37 the planner only read the singular, so every rule
        // derived from a bundle slot had no placement and discovery had no node
        // to ask. R844-F3: it then read only the FIRST entry, which is the same
        // bug one node further along — a workload declared at horizontal scale
        // 2 had its second node dropped from discovery and from the co-located
        // front-door fallback, and the apply still looked clean.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\", \"us-west-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.rules[0].machines, vec!["us-east-001", "us-west-001"]);
        assert_eq!(plan.workload_machines(), vec!["us-east-001", "us-west-001"]);
        // Co-located fallback: one front door per node the workload runs on.
        assert_eq!(
            plan.front_doors,
            vec!["us-east-001".to_string(), "us-west-001".to_string()]
        );
    }

    #[test]
    fn an_empty_machines_list_leaves_the_constraint_fallback_its_turn() {
        // `machines = []` states nothing about placement. Reading it as "placed
        // on the empty set" would shadow the `required` fallback and un-aim
        // discovery, which is the R772 failure with a different spelling.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = []\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let placements = HashMap::from([("bundle".to_string(), vec!["us-east-001".to_string()])]);
        let mut plans = plan_ingress(&m, &placements).expect("mirror plans");
        assert_eq!(plans.remove(0).rules[0].machines, vec!["us-east-001"]);
    }

    #[test]
    fn a_constraint_resolved_placement_set_reaches_every_rule() {
        // The third instance of "caller resolves, planner receives data": the
        // planner never sees `.yah/infra/machines/`, so a set-valued placement
        // arrives as data exactly like a literal list would.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nrequired = { regions = [\"us-east\"] }\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let placements = HashMap::from([(
            "bundle".to_string(),
            vec!["us-east-001".to_string(), "us-south-001".to_string()],
        )]);
        let plan = plan_ingress(&m, &placements)
            .expect("mirror plans")
            .remove(0);
        assert_eq!(plan.rules[0].machines, vec!["us-east-001", "us-south-001"]);
        assert_eq!(
            plan.front_doors,
            vec!["us-east-001".to_string(), "us-south-001".to_string()]
        );
    }

    #[test]
    fn the_co_located_fallback_unions_two_slots_placements() {
        // Two fronted slots on two nodes, no `ingress_machines`. Taking the
        // first rule's node left the second slot's copy with no door in front of
        // it — and the mirror still read as if both were fronted.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachine = \"us-east-001\"\n\
             zone = \"a.yah.dev\"\nport = 8080\n\
             [compute]\nuse = \"hetzner\"\nmachine = \"us-west-001\"\n\
             zone = \"b.yah.dev\"\nport = 9090\n",
        );
        let plan = only_plan(&m);
        assert_eq!(
            plan.front_doors,
            vec!["us-east-001".to_string(), "us-west-001".to_string()]
        );
    }

    #[test]
    fn a_singular_machine_field_still_wins_over_the_plural_one() {
        let m = mirror(
            IngressProvider::Passway,
            "[compute]\nuse = \"hetzner\"\nmachine = \"pinned\"\n\
             machines = [\"ignored\"]\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.rules[0].machines, vec!["pinned"]);
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

    // ── `fronted`: participation split from the port value (R844-F5) ──

    #[test]
    fn a_fronted_slot_with_no_port_is_planned_rather_than_skipped() {
        // The finding this ticket exists for: before the split, deleting `port`
        // did not un-pin a port — it removed the slot from the plan entirely,
        // so a live hostname silently lost its backend while the mirror still
        // read as if it were fronted.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nfronted = true\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].hostname, "yah.dev");
        assert_eq!(plan.rules[0].port, None, "the port is discovery's to answer");
        assert_eq!(plan.rules[0].machines, vec!["us-east-001"]);
        assert_eq!(plan.front_doors, vec!["us-east-001".to_string()]);
    }

    #[test]
    fn a_declared_port_still_fronts_without_the_new_field() {
        // The migration is additive: every mirror on disk predates `fronted`
        // and must plan byte-identically.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachine = \"us-east-001\"\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].port, Some(8080));
    }

    #[test]
    fn a_slot_with_neither_signal_is_still_skipped() {
        // A CDN-published static tier carries `zone` meaning the CLOUDFLARE
        // zone. Keying participation off it would drag every such slot into the
        // plan, which is why `fronted` exists at all.
        let m = mirror(
            IngressProvider::Passway,
            "[static]\nuse = \"cloudflare\"\nbucket = \"b\"\nzone = \"cdn.yah.dev\"\n\
             [bundle]\nuse = \"cloudflare\"\nzone = \"yah.dev\"\nfronted = true\n",
        );
        let plan = only_plan(&m);
        assert_eq!(
            plan.rules.iter().map(|r| r.slot.as_str()).collect::<Vec<_>>(),
            vec!["bundle"]
        );
    }

    #[test]
    fn fronted_without_a_zone_is_the_same_error_as_port_without_one() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nfronted = true\n",
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("providers.bundle"), "got: {msg}");
        assert!(msg.contains("fronted = true"), "names the signal: {msg}");
        assert!(msg.contains("zone"), "got: {msg}");
    }

    #[test]
    fn a_non_boolean_fronted_is_an_error_rather_than_a_silent_skip() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nzone = \"yah.dev\"\nfronted = \"yes\"\n",
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("is not a boolean"), "got: {msg}");
        assert!(msg.contains("providers.bundle"), "got: {msg}");
    }

    #[test]
    fn the_empty_plan_error_names_both_participation_spellings() {
        let m = mirror(
            IngressProvider::Passway,
            "[static]\nuse = \"cloudflare\"\nbucket = \"b\"\n",
        );
        let msg = format!("{:#}", plan_ingress(&m, &HashMap::new()).unwrap_err());
        assert!(msg.contains("fronted = true"), "got: {msg}");
        assert!(msg.contains("`port`"), "got: {msg}");
    }

    // ── resolve_ports (R844-F5) ──

    #[test]
    fn resolve_ports_fills_a_portless_rule_from_discovery() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nfronted = true\nupstream_host = \"100.64.0.3\"\n",
        );
        let mut plan = only_plan(&m);
        // What kamaji allocated and the supervisor reported as `resolved_ports`
        // — a number no mirror could have known.
        plan.resolve_ports(|rule| {
            assert_eq!(rule.slot, "bundle");
            Ok(Some(43117))
        })
        .unwrap();
        assert_eq!(plan.rules[0].port, Some(43117));
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.3:43117"]
        );
    }

    #[test]
    fn a_declared_port_wins_over_discovery() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nzone = \"yah.dev\"\nport = 8080\n\
             fronted = true\nupstream_host = \"100.64.0.3\"\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_ports(|_| panic!("discovery must not run for a pinned port"))
            .unwrap();
        assert_eq!(plan.rules[0].port, Some(8080));
    }

    #[test]
    fn an_unresolved_port_is_one_combined_error_not_a_panic() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nzone = \"yah.dev\"\nfronted = true\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_ports(|_| Ok(None)).unwrap();
        // Neither half resolved: one message naming both, from the single place
        // an undialable rule is reported.
        let msg = format!("{:#}", plan.rules[0].service_url().unwrap_err());
        assert!(msg.contains("no resolved port"), "got: {msg}");
        assert!(msg.contains("no resolved upstream address"), "got: {msg}");
        assert!(msg.contains("providers.bundle"), "got: {msg}");
        assert_eq!(plan.rules[0].port_label(), "<unresolved>");
    }

    #[test]
    fn a_resolved_port_with_no_backend_still_says_so() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nzone = \"yah.dev\"\nfronted = true\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_ports(|_| Ok(Some(43117))).unwrap();
        let err = plan.resolve_upstreams(|_| Ok(Vec::new())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no resolved upstream address"), "got: {msg}");
        assert!(!msg.contains("no resolved port"), "port resolved: {msg}");
    }

    // ── resolve_upstreams_from_config (R844-F12) ──

    fn addrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(n, a)| (n.to_string(), a.to_string()))
            .collect()
    }

    #[test]
    fn a_pinless_slot_takes_its_address_from_the_placement_machines_declaration() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let mut plan = only_plan(&m);
        assert!(
            plan.rules[0].upstream_hosts.is_empty(),
            "nothing pins it, so the planner leaves it for a resolver"
        );
        plan.resolve_upstreams_from_config(&addrs(&[("us-east-001", "100.64.0.3")]));
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.3:8080"],
            "the exact string the pinned mirror renders — equivalence is the claim"
        );
    }

    #[test]
    fn every_placement_machine_contributes_a_backend_in_declaration_order() {
        // Horizontal scale > 1: taking the first entry would render a subset,
        // which is the failure that looks like it worked (R844-F3/F4).
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\n\
             machines = [\"us-east-001\", \"us-west-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_upstreams_from_config(&addrs(&[
            ("us-west-001", "100.64.0.1"),
            ("us-east-001", "100.64.0.3"),
        ]));
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.3:8080", "yah.dev=100.64.0.1:8080"],
            "declaration order, not map order — a reordered set reads as drift \
             on every apply"
        );
    }

    #[test]
    fn a_pinned_upstream_host_still_wins_over_the_declaration() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\nupstream_host = \"10.0.0.9\"\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_upstreams_from_config(&addrs(&[("us-east-001", "100.64.0.3")]));
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["yah.dev=10.0.0.9:8080"],
            "an explicit operator override is the escape hatch for a node whose \
             declared address is wrong — the derivation must not overwrite it"
        );
    }

    #[test]
    fn a_machine_with_no_declared_address_resolves_nothing_rather_than_guessing() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"dev-box\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_upstreams_from_config(&addrs(&[("us-east-001", "100.64.0.3")]));
        // Silence, reported once by the single undialable-rule error site —
        // never a fallback to loopback or to some other node's address.
        let msg = format!("{:#}", plan.passway_upstreams().unwrap_err());
        assert!(msg.contains("no resolved upstream address"), "got: {msg}");
        assert!(!msg.contains("no resolved port"), "port is pinned: {msg}");
    }

    #[test]
    fn a_live_answer_is_not_overwritten_by_the_declaration() {
        // Precedence, stated as a test because the ordering is the whole
        // safety property: discovery reports what the supervisor bound, the
        // declaration reports what a TOML claims, and running this pass after
        // discovery must leave the measured answer alone.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_upstreams(|_| Ok(vec!["100.64.0.42".to_string()]))
            .unwrap();
        plan.resolve_upstreams_from_config(&addrs(&[("us-east-001", "100.64.0.3")]));
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.42:8080"],
            "a stale machine toml must not win over a live read"
        );
    }

    // ── upstream_labels (R844-T10) ──

    #[test]
    fn a_half_resolved_rule_labels_the_half_it_knows() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\"]\n\
             zone = \"yah.dev\"\nfronted = true\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_upstreams_from_config(&addrs(&[("us-east-001", "100.64.0.3")]));
        // The address is a config fact and resolves offline; the port is a
        // runtime fact and cannot. Reporting the first as unknown too — which
        // the old `<unresolved>:<port>` fallback did — discards a fact the tool
        // is holding.
        assert_eq!(
            plan.rules[0].upstream_labels(),
            vec!["100.64.0.3:<unresolved>"]
        );
        assert!(
            plan.rules[0].upstreams().is_err(),
            "and it is still undialable — a label is not a resolution"
        );
    }

    #[test]
    fn a_rule_with_neither_half_says_so_once_per_line() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nzone = \"yah.dev\"\nfronted = true\n",
        );
        let plan = only_plan(&m);
        assert_eq!(
            plan.rules[0].upstream_labels(),
            vec!["<unresolved>:<unresolved>"]
        );
    }

    #[test]
    fn every_backend_gets_its_own_label() {
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\n\
             machines = [\"us-east-001\", \"us-west-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let mut plan = only_plan(&m);
        plan.resolve_upstreams_from_config(&addrs(&[
            ("us-east-001", "100.64.0.3"),
            ("us-west-001", "100.64.0.1"),
        ]));
        assert_eq!(
            plan.rules[0].upstream_labels(),
            vec!["100.64.0.3:8080", "100.64.0.1:8080"],
            "collating one backend out of N is the subset failure this view exists \
             to catch, so the view must not collapse the set either"
        );
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
    fn an_edge_may_name_the_account_its_tunnel_belongs_to() {
        // R845: the fronted slot's compute is an inline `kind = "static"` box —
        // a borrowed machine with no credentials to reference — so there is no
        // slot `use` to read the Cloudflare account off. The edge names it.
        let m = mirror_edges(
            vec![IngressEdge {
                provider_id: Some("cloudflare".into()),
                ..edge(IngressProvider::CloudflareTunnel, &["borrowed-01"], &[])
            }],
            "[compute]\nkind = \"static\"\nmachine = \"borrowed-01\"\n\
             zone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.edge_provider_id.as_deref(), Some("cloudflare"));
        assert_eq!(plan.provider_id(), Some("cloudflare"));
        // The slot still names nothing — that is the whole point. Before this
        // field the only way to satisfy the lookup was to write
        // `use = "cloudflare"` on the compute slot and lie about what runs it.
        assert_eq!(plan.slot_provider_ids().next(), None);
    }

    #[test]
    fn an_edge_use_overrides_the_fronted_slots_own_provider() {
        // The two facts are unrelated: hetzner runs the compute, cloudflare
        // holds the tunnel. Reading the account off the slot conflates them.
        let m = mirror_edges(
            vec![IngressEdge {
                provider_id: Some("cloudflare".into()),
                ..edge(IngressProvider::CloudflareTunnel, &["us-east-001"], &[])
            }],
            "[compute]\nuse = \"hetzner\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.provider_id(), Some("cloudflare"));
        assert_eq!(plan.slot_provider_ids().collect::<Vec<_>>(), vec!["hetzner"]);
    }

    #[test]
    fn without_an_edge_use_the_fronted_slot_still_answers() {
        // Every mirror on disk before R845 — yah-marketing's bundle slot among
        // them — declares no edge `use`, and must plan identically.
        let m = mirror_edges(
            vec![edge(IngressProvider::CloudflareTunnel, &["us-east-001"], &[])],
            "[compute]\nuse = \"cloudflare\"\nzone = \"a.yah.dev\"\nport = 8080\n",
        );
        let plan = only_plan(&m);
        assert_eq!(plan.edge_provider_id, None);
        assert_eq!(plan.provider_id(), Some("cloudflare"));
    }

    #[test]
    fn edge_use_round_trips_through_the_mirror_toml_as_use() {
        // Spelled `use` on the edge exactly as it is on a slot — one word for
        // one concept, or an operator has to learn two.
        let decl: crate::config::IngressDecl = toml::from_str(
            "[[ingress]]\nprovider = \"cloudflare-tunnel\"\nuse = \"cloudflare\"\n",
        )
        .map(|w: EdgeWrapper| w.ingress)
        .expect("edge fixture parses");
        let crate::config::IngressDecl::Edges(edges) = decl else {
            panic!("expected the list form");
        };
        assert_eq!(edges[0].provider_id.as_deref(), Some("cloudflare"));
        let back = toml::to_string(&edges[0]).expect("edge serializes");
        assert!(back.contains("use = \"cloudflare\""), "got: {back}");
    }

    #[derive(serde::Deserialize)]
    struct EdgeWrapper {
        ingress: crate::config::IngressDecl,
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
                port: Some(port),
                slot: "compute".into(),
                provider_id: None,
                machines: Vec::new(),
                upstream_hosts: vec!["100.64.0.5".into()],
            }],
            front_doors: machines.iter().map(|s| s.to_string()).collect(),
            tunnel_id: None,
            edge_provider_id: None,
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
        assert_eq!(
            r.passway_upstreams().unwrap(),
            vec!["a.yah.dev=100.64.0.5:8080"]
        );
    }

    #[test]
    fn a_rule_with_two_backends_renders_both_passway_entries() {
        // R844-F3, the renderer half: passway's grammar load-balances repeated
        // hostnames (`parse_upstream_sets` builds one set per host key), so a
        // workload on two nodes must emit two entries. Collapsing to one is
        // invisible in the config and sends every request to one node.
        let mut r = rule("a.yah.dev", 8080);
        r.upstream_hosts = vec!["100.64.0.5".into(), "100.64.0.9".into()];
        assert_eq!(
            r.passway_upstreams().unwrap(),
            vec!["a.yah.dev=100.64.0.5:8080", "a.yah.dev=100.64.0.9:8080"]
        );
        // The tunnel arm genuinely cannot: one `service` per hostname rule, HA
        // by connector count. It collapses in ONE named place.
        assert_eq!(r.service_url().unwrap(), "http://100.64.0.5:8080");
    }

    #[test]
    fn a_plan_at_scale_two_renders_every_backend() {
        // End to end through the planner: two declared nodes, two discovered
        // addresses, two rendered upstreams. The assertion that fails if any
        // stage collapses the set.
        let m = mirror(
            IngressProvider::Passway,
            "[bundle]\nuse = \"cloudflare\"\nmachines = [\"us-east-001\", \"us-west-001\"]\n\
             zone = \"yah.dev\"\nport = 8080\n",
        );
        let mut plan = only_plan(&m);
        assert_eq!(plan.workload_machines(), vec!["us-east-001", "us-west-001"]);
        plan.resolve_upstreams(|r| {
            assert_eq!(r.machines, vec!["us-east-001", "us-west-001"]);
            Ok(vec!["100.64.0.3".into(), "100.64.0.8".into()])
        })
        .unwrap();
        assert_eq!(
            plan.passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.3:8080", "yah.dev=100.64.0.8:8080"]
        );
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
            assert_eq!(r.port, Some(8080));
            Ok(vec!["100.64.0.7".into()])
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
        let err = plan.resolve_upstreams(|_| Ok(Vec::new())).unwrap_err();
        assert!(format!("{err:#}").contains("no resolved upstream address"));
    }

    // ── merge_tunnel_ingress ──

    /// A rule with its upstream already resolved to a mesh address — what a
    /// plan looks like after `resolve_upstreams`.
    fn rule(hostname: &str, port: u16) -> IngressRule {
        IngressRule {
            hostname: hostname.into(),
            port: Some(port),
            slot: "compute".into(),
            provider_id: None,
            machines: Vec::new(),
            upstream_hosts: vec!["100.64.0.5".into()],
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
