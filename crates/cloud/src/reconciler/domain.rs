//! Domain-level reconciler — `.yah/domains/*.toml` → live Cloudflare state.
//!
//! Today's only shape is the **R2 custom-domain** binding: a domain that
//! declares `front_door = "bucket-direct"` (R594-F12) and names an R2 bucket
//! in `cdn_bucket`. Cloudflare's R2 Custom Domains API binds the hostname to
//! the bucket and writes the CNAME into the parent zone automatically when
//! the zone lives on the same account — no DNS-side call is needed here.
//!
//! Domains with `front_door = "worker"` (e.g. `app-yah-dev.toml`) are out of
//! scope for this shape; they get DNS + route management through the Worker
//! reconciler below. `front_door = "passway"` is the sovereign-ingress path
//! (W267) and is reconciled by [`ensure_passway_apex`] — R859-F1 — which
//! renders the apex A record set from the domain manifest plus the workspace
//! ingress collation, DNS-only, through the provider-agnostic `dns.*` envoy
//! verbs.
//!
//! Before R594-F12 the shape was *inferred* from the absence of `[[routes]]`,
//! which meant a route-carrying manifest bound straight to R2 was accepted
//! and silently skipped by this pass. The discriminator is now declared and
//! validated at load.
//!
//! @yah:relay(R859, "Sovereign-edge automation ring: DNS reconciled from declared intent, public addressing follows placement (W267 audit followups)")
//! @yah:at(2026-09-04T19:06:24Z)
//! @yah:status(handoff)
//! @yah:assignee(agent:user-custom-char-gul2)
//! @arch:see(.yah/docs/working/W267-sovereign-public-ingress.md)
//! @yah:next("Filed from the 2026-09-04 HA/ingress audit (chat session, operator-reviewed). The grey door is live but the automation ring around it is manual: DNS flips ride scripts/cf-apex-mode.sh by hand, and node loss leaves a dead A record taking ~half the round-robin traffic until a human edits DNS.")
//! @yah:next("Order: F1 (DNS reconciler) before F2 (floating-IP wiring) — F2's DNS-withdrawal half needs F1's record-rendering to exist. Sibling track R844-F23 (poll-N door discovery) is independent and filed under R844 where door discovery lives.")
//! @yah:next("Deliberately out of scope here: replica layer (W284/R626), kamaji healthcheck execution, generic appliance backup/migrate (R742-F3), external synthetic prober — each is its own track; this relay is only 'public addressing follows declared intent'.")

use std::path::Path;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::CloudflareClient;

/// Bind `domain` as a custom domain on `bucket_name`. Idempotent — does
/// nothing when the binding is already present, regardless of `enabled`
/// state (CF reflects newly-added bindings as `enabled: true` immediately;
/// disabling is an explicit dashboard action we don't undo here).
///
/// Resolves account_id + the Cloudflare API token from the named provider
/// (`.yah/infra/providers/<provider_id>.toml`, see
/// [`super::cf_creds::CfProvider`]). Mirrors the list-first pattern of
/// `static_asset::ensure_r2_bucket` so the apply loop is safe to re-run.
///
/// Required token scopes: `Workers R2 Storage: Edit` and `Zone: Read`
/// (the latter because the API requires the zone id of the parent zone —
/// CF writes the CNAME there). The caller does NOT need `DNS: Edit`; CF
/// provisions the record itself when the binding is created.
pub async fn ensure_r2_custom_domain(
    workspace_root: &Path,
    provider_id: &str,
    bucket_name: &str,
    domain: &str,
) -> Result<()> {
    let cf_provider = super::cf_creds::CfProvider::resolve(workspace_root, provider_id)?;
    let account_id = cf_provider.account_id.clone();
    let cf = CloudflareClient::new(cf_provider.api_token()?);
    let existing = cf
        .list_r2_custom_domains(&account_id, bucket_name)
        .await
        .with_context(|| format!("listing R2 custom domains on bucket {bucket_name:?}"))?;
    if existing.iter().any(|d| d.domain == domain) {
        debug!(
            domain,
            bucket_name, "R2 custom domain already bound — skipping"
        );
        return Ok(());
    }
    let zone_name = parent_zone_name(domain);
    let zone_id = cf
        .zone_id_for_name(zone_name)
        .await
        .with_context(|| format!("resolving zone id for {zone_name:?}"))?;
    cf.add_r2_custom_domain(&account_id, bucket_name, domain, &zone_id)
        .await
        .with_context(|| format!("binding R2 custom domain {domain:?} → bucket {bucket_name:?}"))?;
    info!(domain, bucket_name, zone_name, "R2 custom domain bound");
    Ok(())
}

/// Heuristic: the parent CF zone of `domain` is its last two labels.
///
/// `cdn.yah.dev` → `yah.dev`; `yah.dev` → `yah.dev` (already apex). This is
/// correct for every yah-owned zone today (all are two-label apexes). If a
/// future workspace registers a three-label zone (e.g. `staging.yah.dev`
/// as its own CF zone) and binds a subdomain under it, this will resolve
/// to the wrong zone — swap in a longest-suffix match against
/// `list_zones()` when that day arrives.
fn parent_zone_name(domain: &str) -> &str {
    let last_dot = domain.rfind('.');
    let Some(last_dot) = last_dot else {
        return domain; // single-label — let CF surface the bad input
    };
    if let Some(prev_dot) = domain[..last_dot].rfind('.') {
        &domain[prev_dot + 1..]
    } else {
        domain // already a two-label apex
    }
}

// ─── R561-F3: domain-manifest-driven static Worker ──────────────────────────
//
// A per-tenant alias-tier manifest (e.g. scrabcake.net.yah.dev) carries a
// `static` route → `<service>/<component>`. Serving it means deploying the
// shared router bundle (`WORKER_SCRIPT`) configured to fetch the tenant's
// assets from its R2 prefix, then binding the subdomain to that Worker via the
// Workers Custom Domains API. This is the routed-domain shape the apply loop
// currently Skips.

use crate::config::{DomainConfig, DomainRoute, FrontDoor, RouteMode};
use crate::provider::cloudflare::WorkerBinding;
use crate::reconciler::mesofact_static::WORKER_SCRIPT;
use std::collections::BTreeMap;

/// The plan for deploying one subdomain's static Worker — everything decided
/// before any Cloudflare call. Pure output of [`plan_domain_worker`], so the
/// decision logic is unit-testable offline; [`deploy_domain_worker`] performs
/// the I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainWorkerPlan {
    /// Worker script name (the domain manifest's file stem / `name`).
    pub worker_name: String,
    /// Hostname to bind via Workers Custom Domains, e.g. `scrabcake.net.yah.dev`.
    pub custom_domain: String,
    /// `ASSET_ORIGIN` the Worker fetches from: `<cdn_base>/<service>/<env>`.
    pub asset_origin: String,
    /// `plain_text` Worker bindings (mirrors the Static-mode shape of
    /// mesofact_static's `worker_config_bindings`).
    pub bindings: Vec<(String, String)>,
}

/// Static-mode Worker bindings for an alias-tier subdomain. Kept in lockstep
/// with `mesofact_static::worker_config_bindings(WorkerMode::Static, …)`.
///
/// `route_headers` is the manifest's own `DomainConfig::route_headers_json` —
/// this planner already holds the domain, so unlike the mirror-driven path it
/// needs no lookup to find it (R746).
fn static_worker_bindings(asset_origin: &str, route_headers: String) -> Vec<(String, String)> {
    vec![
        ("ASSET_ORIGIN".to_string(), asset_origin.to_string()),
        ("UPLOAD_ORIGIN".to_string(), String::new()),
        ("WORKER_MODE".to_string(), "static".to_string()),
        ("SSR_ORIGIN".to_string(), String::new()),
        ("SSR_PREFIXES".to_string(), "[]".to_string()),
        ("ROUTE_HEADERS".to_string(), route_headers),
    ]
}

/// Build the [`DomainWorkerPlan`] for a per-tenant alias-tier manifest.
///
/// `cdn_base` is the tier's CDN origin (an R2 custom domain bound to the
/// tier bucket, e.g. `https://cdn.net.yah.dev`); `env` is the mirror env the
/// publisher wrote under (e.g. `cloud`). The publisher lays assets down at
/// `<bucket>/<service>/<env>/<key>` and the Worker fetches
/// `${ASSET_ORIGIN}/<key>`, so `ASSET_ORIGIN = <cdn_base>/<service>/<env>`.
///
/// Fails fast (before any network call) when the manifest has no `static`
/// route or its component ref is malformed.
pub fn plan_domain_worker(
    domain: &DomainConfig,
    cdn_base: &str,
    env: &str,
) -> Result<DomainWorkerPlan> {
    // R594-F12: refuse to synthesize a Worker for a domain that declared a
    // different front door. Without this the plan succeeds and deploys a
    // Worker that never receives traffic (bucket-direct) or that duplicates
    // the sovereign ingress (passway).
    if domain.front_door != FrontDoor::Worker {
        anyhow::bail!(
            "domain {} ({}) declares front_door = \"{}\" — only \"worker\" \
             domains get a generated Cloudflare Worker",
            domain.name,
            domain.domain,
            domain.front_door.as_str()
        );
    }

    // First static route wins (v1 alias tier serves one site per subdomain).
    let component = domain
        .routes
        .iter()
        .find_map(|r| match &r.mode {
            RouteMode::Static { component } => Some(component.as_str()),
            _ => None,
        })
        .with_context(|| {
            format!(
                "domain {} ({}) has no `static` route — nothing for a static Worker to serve",
                domain.name, domain.domain
            )
        })?;

    let service = component
        .split_once('/')
        .map(|(svc, _)| svc)
        .with_context(|| {
            format!(
                "domain {}: route component {component:?} — expected \"<service>/<component-id>\"",
                domain.name
            )
        })?;

    let asset_origin = format!("{}/{}/{}", cdn_base.trim_end_matches('/'), service, env);

    Ok(DomainWorkerPlan {
        worker_name: domain.name.clone(),
        custom_domain: domain.domain.clone(),
        bindings: static_worker_bindings(&asset_origin, domain.route_headers_json()),
        asset_origin,
    })
}

/// Deploy the planned Worker and bind the subdomain (R561-F3, live I/O).
///
/// Reuses the shared `WORKER_SCRIPT` bundle + the existing CloudflareClient
/// deploy/custom-domain methods. Gated on `cloudflare-api-token`. The decision
/// logic is covered by `plan_domain_worker`'s tests; this I/O path has NOT been
/// exercised against a live account yet (no creds in CI) — treat as untested
/// until a live `yah cloud apply` confirms it.
///
/// CAVEAT (zone resolution): `parent_zone_name` uses a two-label heuristic, so
/// for `scrabcake.net.yah.dev` it returns `yah.dev`. But the alias tiers
/// `net.yah.dev` / `com.yah.dev` are their own Cloudflare zones — the binding
/// must target `net.yah.dev`, not `yah.dev`. Before this goes live, swap in a
/// longest-suffix match against the account's zones (the upgrade path
/// `parent_zone_name`'s doc already names). Tracked on R561-F3.
pub async fn deploy_domain_worker(
    workspace_root: &Path,
    provider_id: &str,
    plan: &DomainWorkerPlan,
) -> Result<()> {
    let cf_provider = super::cf_creds::CfProvider::resolve(workspace_root, provider_id)?;
    let account_id = cf_provider.account_id.clone();
    let cf = CloudflareClient::new(cf_provider.api_token()?);

    let worker_bindings: Vec<WorkerBinding<'_>> = plan
        .bindings
        .iter()
        .map(|(k, v)| WorkerBinding::PlainText {
            name: k.as_str(),
            text: v.as_str(),
        })
        .collect();

    cf.deploy_worker_script(
        &account_id,
        &plan.worker_name,
        WORKER_SCRIPT,
        &worker_bindings,
    )
    .await
    .with_context(|| format!("deploying static Worker {}", plan.worker_name))?;
    info!(worker = %plan.worker_name, "alias-tier Worker deployed");

    let zone = parent_zone_name(&plan.custom_domain);
    let zone_id = cf
        .zone_id_for_name(zone)
        .await
        .with_context(|| format!("resolving zone id for {zone:?}"))?;
    cf.upsert_worker_custom_domain(
        &account_id,
        &zone_id,
        &plan.custom_domain,
        &plan.worker_name,
    )
    .await
    .with_context(|| {
        format!(
            "binding {} to Worker {}",
            plan.custom_domain, plan.worker_name
        )
    })?;
    info!(domain = %plan.custom_domain, worker = %plan.worker_name, "alias-tier custom domain bound");
    Ok(())
}

// ─── R561-F4: alias-tier registration ───────────────────────────────────────
//
// "Claim <name>.{com,net}.yah.dev": validate the label, check it's free, and
// produce the per-tenant DomainConfig (the F2 manifest) the registration flow
// writes. Pure + offline — the SaaS "sign up, get a subdomain" moment.

/// The two wildcard alias tiers. `Com` = managed/commercial, `Net` = community.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasTier {
    Com,
    Net,
}

impl AliasTier {
    /// The tier's Cloudflare zone, e.g. `net.yah.dev`.
    pub fn zone(self) -> &'static str {
        match self {
            AliasTier::Com => "com.yah.dev",
            AliasTier::Net => "net.yah.dev",
        }
    }

    /// The tier's shared R2 bucket (per-tenant `<svc>/<env>` prefixes within).
    pub fn bucket(self) -> &'static str {
        match self {
            AliasTier::Com => "com-yah-dev",
            AliasTier::Net => "net-yah-dev",
        }
    }

    /// Manifest-name infix, e.g. `net` → `<name>-net-yah-dev` file stem.
    fn slug(self) -> &'static str {
        match self {
            AliasTier::Com => "com",
            AliasTier::Net => "net",
        }
    }
}

/// A valid DNS label: 1–63 chars, lowercase alphanumeric or hyphen, no
/// leading/trailing hyphen. (Subdomain names a tenant can claim.)
pub fn valid_subdomain_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validate and build the per-tenant alias manifest for a claim.
///
/// `name` is the requested subdomain label (e.g. `scrabcake`); `component` is
/// the tenant's static component ref (`"<service>/<component-id>"`). `existing`
/// is the current domain map (from `CloudConfig`) — the claim fails if the
/// resulting host or manifest name is already taken. Returns the
/// [`DomainConfig`] to write at `.yah/domains/<stem>.toml`.
pub fn plan_alias_claim(
    tier: AliasTier,
    name: &str,
    component: &str,
    existing: &BTreeMap<String, DomainConfig>,
) -> Result<DomainConfig> {
    if !valid_subdomain_label(name) {
        anyhow::bail!(
            "invalid subdomain {name:?} — must be 1–63 chars, lowercase \
             alphanumeric or hyphen, no leading/trailing hyphen"
        );
    }
    if component.split_once('/').is_none() {
        anyhow::bail!("component {component:?} — expected \"<service>/<component-id>\"");
    }

    let domain = format!("{name}.{}", tier.zone());
    let stem = format!("{name}-{}-yah-dev", tier.slug());

    if existing.values().any(|d| d.domain == domain) {
        anyhow::bail!("{domain} is already claimed");
    }
    if existing.contains_key(&stem) {
        anyhow::bail!("domain manifest {stem:?} already exists");
    }

    Ok(DomainConfig {
        schema_version: 1,
        name: stem,
        domain,
        // R594-F12: every tenant manifest is Worker-served (R561-F3 binds the
        // subdomain as a custom domain on the generated Worker).
        front_door: FrontDoor::Worker,
        cdn_bucket: tier.bucket().to_string(),
        worker_bundle_path: None,
        routes: vec![DomainRoute {
            path: "/*".into(),
            // A claimed alias serves one bundle at the root with no special
            // header needs; a tenant that wants some edits its own manifest.
            headers: BTreeMap::new(),
            mode: RouteMode::Static {
                component: component.to_string(),
            },
        }],
    })
}

// ─── R859-F1: sovereign apex (front_door = "passway") ───────────────────────
//
// The two-source flip this dissolves: `.yah/domains/*.toml` DECLARED
// `front_door`, while `scripts/cf-apex-mode.sh` imperatively MUTATED the apex
// records, and nothing kept the two in agreement. The declaration drifted from
// the live zone for 19 days once (R330-B36) and 4 more (R703-B4). Here the
// manifest is the only source and the reconciler renders the records from it.
//
// Same house shape as the Worker arm: a pure planner (`plan_domain_passway` +
// `diff_apex_records`) that is fully unit-testable offline, and an I/O applier
// (`deploy_domain_passway`) that only executes the diff.

use crate::config::MachineConfig;
use crate::envoy::dns_record::{
    DnsRecordDeleteInput, DnsRecordListInput, DnsRecordUpsertInput,
};
use crate::provider::cloudflare_envoy::CloudflareEnvoy;
use std::net::Ipv4Addr;

/// One declared public origin behind a sovereign apex — a machine that runs a
/// passway front door and carries a routable IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PasswayOrigin {
    /// Machine name, as declared in `.yah/infra/machines/<name>.toml`. Carried
    /// so every error and log line names the box an operator would open.
    pub machine: String,
    /// The address the apex A record will publish.
    pub address: Ipv4Addr,
}

/// What [`public_origins`] resolved: the origins to publish, and the ones it
/// deliberately held back because their machine is confirmed down (R859-F2).
///
/// Two lists rather than one shorter one, because the difference is
/// load-bearing downstream: an origin that is *absent* from a declaration and
/// an origin that is *present and known dead* want opposite treatment when the
/// declaration itself is untrustworthy. See
/// [`DomainPasswayPlan::health_withdrawn`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedOrigins {
    /// Origins the apex should publish.
    pub origins: Vec<PasswayOrigin>,
    /// Declared, resolvable origins withheld because their machine is
    /// confirmed down.
    pub health_withdrawn: Vec<PasswayOrigin>,
}

/// The apex record set one passway domain should carry — pure output of
/// [`plan_domain_passway`], applied by [`deploy_domain_passway`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPasswayPlan {
    /// Parent Cloudflare zone apex name, from [`parent_zone_name`].
    pub zone: String,
    /// FQDN the records live at — the manifest's `domain`.
    pub name: String,
    /// Desired origins, deduplicated and sorted by address so two planning
    /// runs over the same declaration are byte-identical.
    pub origins: Vec<PasswayOrigin>,
    /// Whether [`origins`](Self::origins) is the **whole** declared set.
    ///
    /// `false` when the ingress collation reported problems, because
    /// [`collate_workspace_ingress`](crate::validate::collate_workspace_ingress)
    /// returns `Ok` while *skipping* an edge whose declaration fails to plan —
    /// so a passway edge with a config typo silently drops its machine from
    /// `front_doors`. An absent machine and a withdrawn machine are then
    /// indistinguishable from inside this plan, and the two want opposite
    /// treatment: a withdrawal should prune the record, a typo must not.
    ///
    /// So the flag gates exactly one thing —
    /// [`diff_apex_records`] withholds every prune when it is `false` —
    /// and nothing else. Upserts still happen: growing the fleet must keep
    /// working through an unrelated service's broken declaration, and an
    /// upsert can never make the apex worse. **Fail-closed on withdrawal,
    /// fail-open on addition.**
    pub origins_complete: bool,
    /// Addresses withdrawn because their machine is **confirmed down** —
    /// R859-F2's cross-provider failover, rendered through R859-F1's existing
    /// diff rather than through a second entry point.
    ///
    /// # Why this is not just "absent from `origins`"
    ///
    /// [`origins_complete`](Self::origins_complete) and this field are two
    /// different facts and it is worth being exact about which is which, because
    /// conflating them silently disables the failover this ticket exists for:
    ///
    /// - `origins_complete` answers **"is the *declaration* picture
    ///   trustworthy?"** `false` means the collation skipped an edge, so an
    ///   origin's absence might be a withdrawal or might be a config typo —
    ///   indistinguishable, so every prune is withheld.
    /// - `health_withdrawn` answers **"which declared machine do we know is
    ///   down?"** It is *positive* evidence about a machine the collation
    ///   plainly saw, not an inference from an absence.
    ///
    /// So a health withdrawal is **not** suppressed by `origins_complete =
    /// false`. The discriminator `origins_complete` exists to protect is
    /// exactly "did we see this machine declared?", and for these machines the
    /// answer is yes — they were resolved, taint-checked and address-checked on
    /// the way into this list. A broken edge elsewhere in the workspace says
    /// nothing about a box we watched go down, and letting it veto the
    /// withdrawal would leave a dead origin taking its share of the
    /// round-robin for as long as some unrelated service's TOML is wrong.
    ///
    /// The fail-closed-on-withdrawal rule is not weakened by this: the gate for
    /// a health withdrawal is the *quorum* verdict, applied one layer up in
    /// [`plan_ingress_owner_effect`](crate::provider::floating_ip::plan_ingress_owner_effect),
    /// which refuses to emit the exclusion at all out of a degraded quorum. Two
    /// withdrawal paths, each fail-closed on the evidence that is actually
    /// relevant to it.
    pub health_withdrawn: Vec<PasswayOrigin>,
}

/// One A record currently live at the apex, as read back by
/// `dns.record.list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveApexRecord {
    /// The published address.
    pub content: String,
    /// Whether the provider proxies it (Cloudflare orange-cloud).
    pub proxied: bool,
}

/// What one apply has to change to converge the apex.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApexRecordDiff {
    /// Addresses to upsert as DNS-only A records.
    pub upsert: Vec<String>,
    /// Addresses to remove — surplus A records at the same name.
    pub prune: Vec<String>,
    /// Addresses that *would* have been pruned but were left in place because
    /// [`DomainPasswayPlan::origins_complete`] was `false`.
    ///
    /// Kept rather than dropped so the applier can name the exact records it
    /// declined to touch. A live A record sitting here is the visible symptom
    /// of a broken ingress declaration somewhere in the workspace — it is
    /// either a real withdrawal this apply refused to act on, or an origin the
    /// collation could not see.
    pub withheld_prune: Vec<String>,
}

impl ApexRecordDiff {
    /// `true` when this apply has no write to make. Withheld prunes do not
    /// count: they are deliberately not writes, and a converged-with-withheld
    /// diff still has something to warn about.
    pub fn is_converged(&self) -> bool {
        self.upsert.is_empty() && self.prune.is_empty()
    }
}

/// What [`deploy_domain_passway`] actually did, for the apply summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswayApexOutcome {
    /// Addresses written (created or re-pointed to DNS-only).
    pub upserted: Vec<String>,
    /// Addresses withdrawn.
    pub pruned: Vec<String>,
    /// Addresses left in place that the declaration no longer names, because
    /// the ingress collation was incomplete — see
    /// [`DomainPasswayPlan::origins_complete`]. Surfaced in the outcome (not
    /// only in the log) so `yah cloud apply` can print it: a withheld prune is
    /// the operator's cue that some service's ingress declaration is broken.
    pub withheld_prune: Vec<String>,
}

impl PasswayApexOutcome {
    /// `true` when the live apex already matched the declaration and nothing
    /// was written.
    pub fn is_noop(&self) -> bool {
        self.upserted.is_empty() && self.pruned.is_empty()
    }
}

/// Parse `address` as a **publicly routable** IPv4, naming `machine` on
/// failure.
///
/// This is the publicness cross-check nothing performs today: the `public-ip`
/// taint and `connect.address` are two independent operator declarations, and
/// [`crate::config::ConnectSpec::address`]'s own doc warns it is *whichever*
/// address the operator chose to dial the box on — public, LAN, or tailnet
/// (us-west-002 is deliberately pointed at its tailnet IP, R608-F10). Publishing
/// a `100.64.0.x` or `192.168.x.x` A record on a public apex takes its share of
/// the round-robin straight to a black hole, so a taint/address disagreement
/// has to be a hard error rather than a silently-broken record.
///
/// Kept local to this arm on purpose (R859-F1 decision 4): a workspace-wide
/// lint would fire on every machine that carries the taint for placement
/// reasons while being dialled over the mesh, which is legitimate.
fn public_ipv4_for(machine: &str, address: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = address.parse().map_err(|_| {
        anyhow::anyhow!(
            "machine {machine}: connect.address = {address:?} is not an IPv4 address, so it \
             cannot be published as an apex A record. Either set it to the box's public IPv4 \
             or drop the `public-ip` taint from {machine}.toml."
        )
    })?;
    let o = ip.octets();
    // 100.64.0.0/10 — RFC 6598 shared address space, which is also the
    // tailnet range this fleet's mesh addresses live in.
    let is_cgnat = o[0] == 100 && (64..=127).contains(&o[1]);
    let reason = if ip.is_unspecified() {
        Some("unspecified")
    } else if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_private() {
        Some("RFC 1918 private")
    } else if ip.is_link_local() {
        Some("link-local")
    } else if is_cgnat {
        Some("RFC 6598 shared / tailnet")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if ip.is_broadcast() {
        Some("broadcast")
    } else {
        None
    };
    if let Some(reason) = reason {
        anyhow::bail!(
            "machine {machine}: connect.address = {address:?} is a {reason} address, not a \
             public one — publishing it at a public apex would black-hole its share of the \
             round-robin. Set connect.address to the box's public IPv4 or drop the \
             `public-ip` taint from {machine}.toml."
        );
    }
    Ok(ip)
}

/// Resolve collated front-door machine names to the public origins the apex
/// should publish (R859-F1).
///
/// Keeps only machines carrying the [`workload_spec::PUBLIC_IP_TAINT`]
/// affinity taint — the same declaration that makes yubaba willing to place a
/// public ingress appliance there — and reads each one's
/// [`ConnectSpec::address`](crate::config::ConnectSpec::address). A named
/// machine that is absent from `machines` is an error, not a silent drop: the
/// alternative is an apex that quietly shrinks because a machine TOML was
/// renamed.
///
/// Machines without the taint are skipped silently. That is the intended
/// filter, not a swallowed error — a passway edge may be collated onto a
/// mesh-only box that fronts internal hostnames.
///
/// # `health_excluded` — R859-F2's withdrawal seam
///
/// Machines named in `health_excluded` are declared, resolvable, and dropped
/// from the origin list anyway, because something confirmed they are down. The
/// resulting shorter list flows through [`plan_domain_passway`] and
/// [`diff_apex_records`] unchanged, so the withdrawal renders as an ordinary
/// prune and needs no second entry point — the whole point of extending this
/// function rather than adding a parallel one.
///
/// Exclusions are returned separately (see [`ResolvedOrigins`]) rather than
/// silently vanishing, because "declared but withheld for health" is a
/// different fact from "never declared", and [`diff_apex_records`] has to be
/// able to tell them apart. See [`DomainPasswayPlan::health_withdrawn`].
///
/// An excluded machine is still *resolved* first: it must exist, carry the
/// taint and have a public address, exactly as if it were staying. Skipping
/// those checks would let a health exclusion paper over a config error, and a
/// machine we cannot resolve is one we cannot honestly say we are withdrawing.
///
/// A name in `health_excluded` that is not a front door at all is ignored — the
/// caller's liveness view covers the whole fleet, and most of it never fronts
/// anything.
pub fn public_origins(
    front_door_machines: &[String],
    machines: &[MachineConfig],
    health_excluded: &[String],
) -> Result<ResolvedOrigins> {
    let mut resolved = ResolvedOrigins::default();
    for name in front_door_machines {
        let machine = machines
            .iter()
            .find(|m| &m.name == name)
            .with_context(|| {
                format!(
                    "front door collated onto machine {name:?}, which is in neither this \
                     camp's own .yah/infra/machines/*.toml nor any fleet it borrows through \
                     .yah/infra/sources.toml — cannot resolve its public address"
                )
            })?;
        if !machine
            .taints
            .iter()
            .any(|t| t == workload_spec::PUBLIC_IP_TAINT)
        {
            debug!(
                machine = %name,
                "front-door machine has no `public-ip` taint — not an apex origin"
            );
            continue;
        }
        let address = machine
            .connect
            .as_ref()
            .map(|c| c.address.as_str())
            .with_context(|| {
                format!(
                    "machine {name} carries the `public-ip` taint but declares no \
                     [connect] address — nothing to publish at the apex"
                )
            })?;
        let origin = PasswayOrigin {
            machine: name.clone(),
            address: public_ipv4_for(name, address)?,
        };
        if health_excluded.iter().any(|m| m == name) {
            debug!(
                machine = %name,
                address = %origin.address,
                "front-door machine confirmed down — withheld from the apex origin set"
            );
            resolved.health_withdrawn.push(origin);
        } else {
            resolved.origins.push(origin);
        }
    }
    Ok(resolved)
}

/// Build the apex record plan for a `front_door = "passway"` manifest.
///
/// Refuses two shapes outright:
///
/// 1. A manifest declaring a different front door — the same guard
///    [`plan_domain_worker`] carries, for the same reason.
/// 2. An **empty** origin set. The desired set is what the applier prunes
///    against, so an empty one would not mean "leave it alone", it would mean
///    "delete every A record at the apex" — a live outage rendered from a
///    collation that simply found nothing. Nothing about "no machine is
///    declared" says "take the site down", so it is an error.
///
/// That empty-set guard is checked **before** `origins_complete` is consulted:
/// an empty set is unusable whether or not the collation was clean, so it stays
/// the louder failure.
///
/// `origins_complete` is the caller's answer to "did the collation see the
/// whole picture?" — `false` withholds every prune downstream. See
/// [`DomainPasswayPlan::origins_complete`].
///
/// # The empty-set guard is also the health failover's backstop (R859-F2)
///
/// Guard 2 is checked against the origins that **survive** health exclusion, and
/// that is the load-bearing interaction of this whole feature: if every declared
/// front door is confirmed down, `origins` is empty and this refuses. "All our
/// front doors are down" must never render as "withdraw every A record and take
/// the site down" — a dead origin still in DNS is a partial outage, an empty
/// apex is a total one, and between those the first is strictly better. So the
/// health withdrawal is capped at "all but the last origin" by construction,
/// with no separate rule to keep in sync.
///
/// An address that is *also* served by a surviving origin is dropped from
/// [`health_withdrawn`](DomainPasswayPlan::health_withdrawn) for the same
/// reason, one level finer: two machines can share a floating IP (the dedup
/// comment below names that case), and pruning the record because one of them
/// died would withdraw an address the other is still answering on.
pub fn plan_domain_passway(
    domain: &DomainConfig,
    resolved: ResolvedOrigins,
    origins_complete: bool,
) -> Result<DomainPasswayPlan> {
    let ResolvedOrigins {
        origins,
        health_withdrawn,
    } = resolved;
    if domain.front_door != FrontDoor::Passway {
        anyhow::bail!(
            "domain {} ({}) declares front_door = \"{}\" — only \"passway\" domains \
             get a sovereign apex rendered here",
            domain.name,
            domain.domain,
            domain.front_door.as_str()
        );
    }

    // By address, not by machine name: the address is what lands in DNS, so
    // ordering on it is what makes two planning runs byte-identical even if a
    // box is renamed. Dedup on the same key — two edges collated onto one
    // machine (or two machines sharing a floating IP) publish one record.
    let mut origins = origins;
    origins.sort_by(|a, b| (a.address, &a.machine).cmp(&(b.address, &b.machine)));
    origins.dedup_by(|a, b| a.address == b.address);

    if origins.is_empty() {
        anyhow::bail!(
            "domain {} ({}) declares front_door = \"passway\" but no declared front-door \
             machine carries the `public-ip` taint with a public address — refusing to \
             render an empty apex, which would withdraw every A record and take the site \
             down. Declare the ingress edge's machines (or their taints) first.",
            domain.name,
            domain.domain
        );
    }

    // Same normalisation as `origins`, plus the survivor filter: an address a
    // live origin still answers on is not withdrawn, however many of the
    // machines sharing it went down.
    let mut health_withdrawn = health_withdrawn;
    health_withdrawn.retain(|w| !origins.iter().any(|o| o.address == w.address));
    health_withdrawn.sort_by(|a, b| (a.address, &a.machine).cmp(&(b.address, &b.machine)));
    health_withdrawn.dedup_by(|a, b| a.address == b.address);

    Ok(DomainPasswayPlan {
        zone: parent_zone_name(&domain.domain).to_string(),
        name: domain.domain.clone(),
        origins,
        origins_complete,
        health_withdrawn,
    })
}

/// Diff the planned apex against the A records live at that name.
///
/// `live` must already be narrowed to **type A at `plan.name`** — MX, TXT and
/// AAAA records share the apex and are never this arm's to touch.
///
/// A live record whose content is desired but which is *proxied* still lands in
/// `upsert`: orange-cloud is a break-glass state
/// (`scripts/cf-apex-mode.sh orange`) and this reconciler declares DNS-only, so
/// re-writing the record with `proxied = false` is convergence, not churn.
///
/// When [`plan.origins_complete`](DomainPasswayPlan::origins_complete) is
/// `false` the surplus records move to
/// [`withheld_prune`](ApexRecordDiff::withheld_prune) instead of `prune`, and
/// `upsert` is unaffected. An incomplete collation cannot tell a withdrawn
/// origin from one whose declaration failed to plan, and only one of those two
/// wants a DNS withdrawal.
///
/// # …with one exception, and it is the point of R859-F2
///
/// A surplus address that appears in
/// [`plan.health_withdrawn`](DomainPasswayPlan::health_withdrawn) is pruned
/// **regardless of `origins_complete`**. The two flags are not two strengths of
/// the same doubt, they are answers to different questions, and the four cases
/// come out like this:
///
/// | `origins_complete` | in `health_withdrawn` | verdict |
/// |---|---|---|
/// | `true`  | no  | `prune` — an ordinary withdrawal from a trusted declaration |
/// | `true`  | yes | `prune` — a health withdrawal from a trusted declaration |
/// | `false` | no  | `withheld_prune` — might be a withdrawal, might be a typo |
/// | `false` | yes | `prune` — we saw this machine declared *and* saw it die |
///
/// The bottom-right cell is the one that matters. `origins_complete = false`
/// protects against mistaking an absence for a withdrawal; a health withdrawal
/// is not an absence, it is a positive observation about a machine the
/// collation resolved. An unrelated service's broken TOML is not evidence about
/// a box we watched go down, and letting it withhold the prune would leave a
/// dead origin serving its share of the round-robin for as long as that typo
/// lives.
pub fn diff_apex_records(plan: &DomainPasswayPlan, live: &[LiveApexRecord]) -> ApexRecordDiff {
    let desired: Vec<String> = plan
        .origins
        .iter()
        .map(|o| o.address.to_string())
        .collect();
    let upsert = desired
        .iter()
        .filter(|ip| {
            !live
                .iter()
                .any(|r| &&r.content == ip && !r.proxied)
        })
        .cloned()
        .collect();
    let surplus: Vec<String> = live
        .iter()
        .filter(|r| !desired.contains(&r.content))
        .map(|r| r.content.clone())
        .collect();
    if plan.origins_complete {
        return ApexRecordDiff {
            upsert,
            prune: surplus,
            withheld_prune: Vec::new(),
        };
    }
    // Incomplete declaration: withhold every prune EXCEPT the health
    // withdrawals, which rest on a positive observation rather than on an
    // absence. See this function's doc table.
    let withdrawn: Vec<String> = plan
        .health_withdrawn
        .iter()
        .map(|o| o.address.to_string())
        .collect();
    let (prune, withheld_prune) = surplus
        .into_iter()
        .partition(|content| withdrawn.contains(content));
    ApexRecordDiff {
        upsert,
        prune,
        withheld_prune,
    }
}

/// Resolve the DNS adapter one passway apply talks to.
///
/// Its own function only so the read path and the write path cannot drift onto
/// different credentials or a different provider seam.
fn passway_envoy(workspace_root: &Path, provider_id: &str) -> Result<CloudflareEnvoy> {
    let cf_provider = super::cf_creds::CfProvider::resolve(workspace_root, provider_id)?;
    Ok(CloudflareEnvoy::new(
        cf_provider.api_token()?,
        cf_provider.account_id.clone(),
    ))
}

/// The `list` leg of [`deploy_domain_passway`] — the live A records at one
/// name, as `dns.record.list` reports them.
///
/// Takes `zone`/`name` rather than a [`DomainPasswayPlan`] because the
/// no-door-declared branch of [`ensure_passway_apex`] has to read the apex
/// *without* a plan — there are no origins to build one from, and whether the
/// apex is currently serving is exactly the question it needs answered.
async fn read_live_apex(
    envoy: &CloudflareEnvoy,
    zone: &str,
    name: &str,
) -> Result<Vec<LiveApexRecord>> {
    let listed = envoy
        .dns_record_list(DnsRecordListInput {
            zone: zone.to_string(),
            name: Some(name.to_string()),
            record_type: Some("A".to_string()),
        })
        .await
        .with_context(|| format!("listing A records at {name}"))?;
    Ok(listed
        .records
        .into_iter()
        .map(|r| LiveApexRecord {
            content: r.content,
            proxied: r.proxied,
        })
        .collect())
}

/// Read the live apex A records **without being able to write any** — the
/// read-only half of [`deploy_domain_passway`], exposed so convergence can be
/// checked against a real Cloudflare account by something that has no write
/// path at all (R859-F1's live acceptance check,
/// `tests/passway_apex_live.rs`).
///
/// Pair it with [`plan_passway_apex`] and [`diff_apex_records`] to answer "what
/// would `yah cloud apply` change?" against live DNS. That is the *whole* of
/// what an apply decides — same planner, same list verb, same diff — minus the
/// two `dns.record.upsert` / `dns.record.delete` calls, which this function
/// cannot reach. A caller can therefore assert convergence against the real
/// zone without a live-DNS blast radius, which is what makes the check safe to
/// leave runnable rather than described in a handoff.
pub async fn list_live_apex_records(
    workspace_root: &Path,
    provider_id: &str,
    plan: &DomainPasswayPlan,
) -> Result<Vec<LiveApexRecord>> {
    let envoy = passway_envoy(workspace_root, provider_id)?;
    read_live_apex(&envoy, &plan.zone, &plan.name).await
}

/// Apply a [`DomainPasswayPlan`] against live DNS (R859-F1, live I/O).
///
/// **First production consumer of the `dns.*` envoy verbs** — every read and
/// write here goes through [`CloudflareEnvoy`]'s typed verb handlers rather
/// than the `CloudflareClient` methods the older arms call directly, so
/// swapping the DNS provider is a matter of resolving a different adapter here
/// and nothing else.
///
/// Two invariants, both borrowed from `scripts/cf-apex-mode.sh`, whose
/// behaviour this replaces for the routine case:
///
/// - **List first, skip when converged.** Same shape as
///   [`ensure_r2_custom_domain`], so a re-run of `yah cloud apply` writes
///   nothing.
/// - **Upsert before prune.** Desired records are written first and surplus
///   ones removed last, so the apex is never momentarily recordless. Only
///   `A` records at the name are ever pruned; the apex's MX and TXT records
///   (mail routing, SPF, site verification) are outside the filter by
///   construction.
/// - **Fail-closed on withdrawal, fail-open on addition.** When the plan says
///   the origin set is incomplete
///   ([`origins_complete = false`](DomainPasswayPlan::origins_complete)) the
///   upserts still run but every prune is withheld and warned about — an
///   absent origin might be a withdrawal or might be a config typo upstream,
///   and only one of those should take a live record away.
///
/// Always writes `proxied = false`: the manifest cannot express grey vs
/// orange, and orange stays break-glass in the script (W267 tier ladder).
pub async fn deploy_domain_passway(
    workspace_root: &Path,
    provider_id: &str,
    plan: &DomainPasswayPlan,
) -> Result<PasswayApexOutcome> {
    let envoy = passway_envoy(workspace_root, provider_id)?;
    let live = read_live_apex(&envoy, &plan.zone, &plan.name).await?;

    let diff = diff_apex_records(plan, &live);

    // Warned before the converged early-return: a withheld prune is worth
    // saying out loud even on an apply that writes nothing, because the record
    // it names stays live until someone fixes the declaration.
    if !diff.withheld_prune.is_empty() {
        warn!(
            domain = %plan.name,
            withheld = %diff.withheld_prune.join(", "),
            "apex A records NOT withdrawn: the ingress collation reported problems, so an \
             origin missing from it may be a broken declaration rather than a withdrawal. \
             Run `yah cloud validate` and fix the reported ingress declaration; these \
             records stay live until the collation is clean."
        );
    }

    if diff.is_converged() {
        debug!(
            domain = %plan.name,
            origins = plan.origins.len(),
            "sovereign apex already matches the declaration — skipping"
        );
        return Ok(PasswayApexOutcome {
            withheld_prune: diff.withheld_prune,
            ..Default::default()
        });
    }

    // Writes first: never leave the apex without a routing record.
    for ip in &diff.upsert {
        envoy
            .dns_record_upsert(DnsRecordUpsertInput {
                zone: plan.zone.clone(),
                name: plan.name.clone(),
                record_type: "A".to_string(),
                content: ip.clone(),
                ttl: 1,
                proxied: false,
                // A round-robin apex is a multi-valued RRset: without this the
                // second origin would overwrite the first.
                match_content: true,
            })
            .await
            .with_context(|| format!("upserting A {} -> {ip}", plan.name))?;
        info!(domain = %plan.name, origin = %ip, "sovereign apex A record written");
    }

    // Prune last, and only ever type A carrying an undeclared value.
    for ip in &diff.prune {
        envoy
            .dns_record_delete(DnsRecordDeleteInput {
                zone: plan.zone.clone(),
                name: plan.name.clone(),
                record_type: Some("A".to_string()),
                content: Some(ip.clone()),
            })
            .await
            .with_context(|| format!("pruning surplus A {} -> {ip}", plan.name))?;
        info!(domain = %plan.name, origin = %ip, "surplus apex A record withdrawn");
    }

    Ok(PasswayApexOutcome {
        upserted: diff.upsert,
        pruned: diff.prune,
        withheld_prune: diff.withheld_prune,
    })
}

/// Reconcile one `front_door = "passway"` domain end to end — the entry point
/// `yah cloud apply` calls (R859-F1).
///
/// Collates the workspace's declared ingress edges, keeps the passway front
/// doors, resolves their machines to public addresses, plans, and applies.
/// Every input is *declared* config: no network read decides which origins the
/// apex publishes, which is what makes the manifest the single source the
/// two-source flip lacked.
///
/// The planning half is [`plan_passway_apex`] (which also carries the
/// `report.problems` prune gate); this function is that plan handed to
/// [`deploy_domain_passway`].
///
/// # `Ok(None)`: the door is declared but not stood up yet
///
/// A camp can legitimately declare `front_door = "passway"` on a domain whose
/// passway edge does not exist yet — the manifest field is how you *say* which
/// door you intend, and R859-F1 made it the mechanism as well, so it is written
/// before the edge is. The noisetable camp is exactly this: `noisetable.com`
/// declares `passway`, its only ingress edge is a `cloudflare-tunnel` on a
/// different domain, and its apex is deliberately NXDOMAIN pending a node.
///
/// Treating that as an error would have been wrong twice over. It fails the
/// whole `yah cloud apply` — the domain loop `bail!`s at the first failure
/// without `--continue-on-error` — so one not-yet-built door takes down the
/// publish chain for every service and every other domain in the camp. And the
/// empty-apex guard it would trip
/// ([`plan_domain_passway`]'s "refusing to render an empty apex") exists to
/// prevent a *wipe*, which skipping prevents equally well: this arm writes
/// nothing at all on this path.
///
/// So "no passway edge collated" is `Ok(None)` — but only after checking that
/// the apex is not **currently serving**. Those are two different worlds and
/// only a DNS read tells them apart:
///
/// - Nothing live at the name → the door was never stood up. Skip.
/// - Records live at the name → an edge that WAS fronting this apex has
///   vanished from the collation, and the next apply would otherwise silently
///   leave orphaned records pointing at whatever used to serve. That is a hard
///   error, and it is the case the empty-apex guard was really written for.
///
/// The read costs nothing extra in practice: this arm only runs inside the
/// domain pass, which already resolved a Cloudflare provider and an
/// `account_id` before entering the loop.
pub async fn ensure_passway_apex(
    workspace_root: &Path,
    provider_id: &str,
    domain: &DomainConfig,
) -> Result<Option<PasswayApexOutcome>> {
    let Some(plan) = plan_passway_apex(workspace_root, domain)? else {
        let zone = parent_zone_name(&domain.domain).to_string();
        let envoy = passway_envoy(workspace_root, provider_id)?;
        let live = read_live_apex(&envoy, &zone, &domain.domain).await?;
        if live.is_empty() {
            debug!(
                domain = %domain.domain,
                "declares front_door = \"passway\" with no passway ingress edge collated, and \
                 nothing is live at the apex — nothing to render, skipping"
            );
            return Ok(None);
        }
        anyhow::bail!(
            "domain {} ({}) declares front_door = \"passway\" and {} A record(s) are live at \
             the apex ({}), but no passway ingress edge collates onto it. An edge that was \
             fronting this apex has disappeared from the declaration, and these records now \
             point at whatever used to serve. Restore the ingress edge, or move the domain \
             off `passway`, before applying again.",
            domain.name,
            domain.domain,
            live.len(),
            live.iter()
                .map(|r| r.content.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
    };
    deploy_domain_passway(workspace_root, provider_id, &plan)
        .await
        .map(Some)
}

/// The pure half of [`ensure_passway_apex`]: collate, resolve, plan — no
/// network, no credential, no write path.
///
/// Split out so the apex a given workspace *would* publish can be computed by a
/// caller that must not be able to change it. `yah cloud apply` reaches it only
/// through [`ensure_passway_apex`]; the live acceptance check
/// (`tests/passway_apex_live.rs`) calls it directly and pairs it with
/// [`list_live_apex_records`], so the check exercises this exact planner rather
/// than a second copy of its logic that could agree with the live zone while
/// production disagreed.
///
/// Every input is *declared* config: no network read decides which origins the
/// apex publishes, which is what makes the manifest the single source the
/// two-source flip lacked.
///
/// ## Why `report.problems` gates the prune
///
/// [`collate_workspace_ingress`](crate::validate::collate_workspace_ingress)
/// returns `Ok` while **skipping** an edge whose declaration fails to plan
/// (`validate.rs`, the `IngressProblem::Declaration` arms). A passway edge with
/// a config typo therefore drops its machine out of `front_doors` silently, and
/// from inside the plan that is indistinguishable from the operator having
/// withdrawn the node — so without this gate a typo would render as a DNS
/// withdrawal and take that origin's share of the apex offline.
///
/// Any non-empty `problems` therefore sets `origins_complete = false`, which
/// withholds every prune for this apply. Deliberately *not* narrowed to the
/// problems that mention this domain's edge: attributing a problem to an edge
/// requires the very planning that failed, and "non-empty means the picture is
/// incomplete" is the whole of what the prune path needs to know. Equally
/// deliberately, problems do **not** fail the arm — one service's broken
/// ingress declaration must not block another's DNS apply, and upserts can
/// only ever add reachable origins.
///
/// ## `Ok(None)` — no passway edge collates at all
///
/// Distinct from every error this can return, and the distinction is the whole
/// point: a camp that declares `front_door = "passway"` before building the
/// door has made no mistake, and must not have its apply failed for it. See
/// [`ensure_passway_apex`], which decides what to do about it (and is the one
/// that can tell "never stood up" from "the door vanished", because that takes
/// a DNS read this pure function must not make).
///
/// Note the narrowness: `None` means the *collation* produced no passway edge.
/// A declared edge whose machine lacks the `public-ip` taint, or carries a
/// private address, still reaches [`plan_domain_passway`] and still trips its
/// empty-apex guard as an error — an intended door that resolves to nothing is
/// a misconfiguration, not an absence.
pub fn plan_passway_apex(
    workspace_root: &Path,
    domain: &DomainConfig,
) -> Result<Option<DomainPasswayPlan>> {
    let report = crate::validate::collate_workspace_ingress(workspace_root)
        .context("collating workspace ingress to find the passway front doors")?;

    let origins_complete = report.problems.is_empty();
    if !origins_complete {
        for problem in &report.problems {
            warn!(
                domain = %domain.domain,
                "ingress collation problem — apex prunes withheld this apply: {}",
                problem.message()
            );
        }
    }

    let mut front_door_machines: Vec<String> = report
        .collation
        .front_doors
        .iter()
        .filter(|fd| fd.provider == crate::config::IngressProvider::Passway)
        .map(|fd| fd.machine.clone())
        .collect();
    front_door_machines.sort();
    front_door_machines.dedup();

    // The door is declared but not built yet. Answered here rather than left to
    // plan_domain_passway's empty-apex guard, because an absent edge and an
    // edge that resolves to no public address want opposite treatment.
    if front_door_machines.is_empty() {
        return Ok(None);
    }

    // R870-B13: the camp's resolved fleet inventory, not its camp-local
    // machine files. A camp that BORROWS another camp's fleet (empty
    // `.yah/infra/machines/`, one `[[source]]` link in
    // `.yah/infra/sources.toml`) declares no machines of its own, so reading
    // the camp-local loader here failed the apex render on a front-door
    // machine that was declared all along — in the owner's tree, which the
    // link names. The inventory is the one reader every name lookup shares.
    let inventory = crate::config::resolve_fleet_inventory(workspace_root)
        .context("resolving the fleet inventory to place the apex origins")?;

    // R859-F2: no health exclusions on the `yah cloud apply` path, deliberately
    // and not as a stub. The confirmed-down fact is a *fleet-runtime* one —
    // it comes from a leader's lease hysteresis, gated on a healthy quorum
    // (`plan_ingress_owner_effect`) — and `yah cloud apply` is an operator
    // running a declarative converge from a laptop, which holds no such view.
    // Feeding it a liveness guess here would let a laptop with a flaky uplink
    // withdraw a live origin. The exclusion set enters through the effector
    // that *has* the fact; this path renders the declaration as declared.
    //
    // The source accounting rides along on the error rather than the success
    // path: "no such machine" reads identically whether this camp declared no
    // link, aimed one at a directory that is not a camp, or filtered the
    // machine out with `select`, and the operator needs to know which.
    let resolved =
        public_origins(&front_door_machines, &inventory.machines, &[]).map_err(|e| {
            let sources = inventory.describe_sources();
            if sources.is_empty() {
                e
            } else {
                e.context(sources)
            }
        })?;
    plan_domain_passway(domain, resolved, origins_complete).map(Some)
}

#[cfg(test)]
mod tests {
    use super::parent_zone_name;

    #[test]
    fn parent_zone_strips_one_label_off_subdomain() {
        assert_eq!(parent_zone_name("cdn.yah.dev"), "yah.dev");
        assert_eq!(parent_zone_name("app.yah.dev"), "yah.dev");
    }

    #[test]
    fn parent_zone_returns_self_for_apex() {
        assert_eq!(parent_zone_name("yah.dev"), "yah.dev");
    }

    #[test]
    fn parent_zone_strips_only_first_label_for_deeper_subdomain() {
        // Two-label heuristic: yah-side zones are all two-label apexes today.
        assert_eq!(parent_zone_name("a.b.yah.dev"), "yah.dev");
    }

    use super::{plan_domain_worker, DomainWorkerPlan};
    use crate::config::{DomainConfig, DomainRoute, FrontDoor, RouteMode};

    fn net_tier_manifest() -> DomainConfig {
        // Mirrors .yah/domains/scrabcake-net-yah-dev.toml.
        DomainConfig {
            schema_version: 1,
            name: "scrabcake-net-yah-dev".into(),
            domain: "scrabcake.net.yah.dev".into(),
            front_door: FrontDoor::Worker,
            cdn_bucket: "net-yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                headers: Default::default(),
                path: "/*".into(),
                mode: RouteMode::Static {
                    component: "scrabcake/site".into(),
                },
            }],
        }
    }

    #[test]
    fn plan_resolves_worker_name_domain_and_asset_origin() {
        let plan =
            plan_domain_worker(&net_tier_manifest(), "https://cdn.net.yah.dev", "cloud").unwrap();
        assert_eq!(
            plan,
            DomainWorkerPlan {
                worker_name: "scrabcake-net-yah-dev".into(),
                custom_domain: "scrabcake.net.yah.dev".into(),
                asset_origin: "https://cdn.net.yah.dev/scrabcake/cloud".into(),
                bindings: vec![
                    (
                        "ASSET_ORIGIN".into(),
                        "https://cdn.net.yah.dev/scrabcake/cloud".into()
                    ),
                    ("UPLOAD_ORIGIN".into(), String::new()),
                    ("WORKER_MODE".into(), "static".into()),
                    ("SSR_ORIGIN".into(), String::new()),
                    ("SSR_PREFIXES".into(), "[]".into()),
                    ("ROUTE_HEADERS".into(), "[]".into()),
                ],
            }
        );
    }

    /// R746: headers declared on a route reach the deployed Worker as the
    /// ROUTE_HEADERS binding. Without this the manifest could declare them and
    /// the Worker would serve without them — the exact silent gap the primitive
    /// exists to close.
    #[test]
    fn plan_carries_declared_route_headers_into_the_bindings() {
        let mut dom = net_tier_manifest();
        dom.routes[0].headers = [
            ("Cross-Origin-Opener-Policy".to_string(), "same-origin".to_string()),
            (
                "Cross-Origin-Embedder-Policy".to_string(),
                "require-corp".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let plan = plan_domain_worker(&dom, "https://cdn.net.yah.dev", "cloud").unwrap();
        let binding = plan
            .bindings
            .iter()
            .find(|(k, _)| k == "ROUTE_HEADERS")
            .expect("ROUTE_HEADERS binding");
        assert!(binding.1.contains("same-origin"), "{}", binding.1);
        assert!(binding.1.contains("require-corp"), "{}", binding.1);
        assert!(binding.1.contains("/*"), "{}", binding.1);
    }

    #[test]
    fn plan_trims_trailing_slash_on_cdn_base() {
        let plan =
            plan_domain_worker(&net_tier_manifest(), "https://cdn.net.yah.dev/", "cloud").unwrap();
        assert_eq!(plan.asset_origin, "https://cdn.net.yah.dev/scrabcake/cloud");
    }

    /// R594-F12: a manifest that declares a different front door must not
    /// get a Cloudflare Worker synthesized behind its back — the Worker
    /// would deploy and then never receive traffic.
    #[test]
    fn plan_bails_when_front_door_is_not_worker() {
        for door in [FrontDoor::BucketDirect, FrontDoor::Passway] {
            let mut dom = net_tier_manifest();
            dom.front_door = door;
            let err = plan_domain_worker(&dom, "https://cdn.net.yah.dev", "cloud").unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("front_door"), "{msg}");
            assert!(msg.contains(door.as_str()), "{msg}");
        }
    }

    #[test]
    fn plan_bails_when_no_static_route() {
        let mut dom = net_tier_manifest();
        dom.routes = vec![DomainRoute {
            headers: Default::default(),
            path: "/old".into(),
            mode: RouteMode::Redirect {
                target: "https://elsewhere".into(),
                status: 308,
            },
        }];
        let err = plan_domain_worker(&dom, "https://cdn.net.yah.dev", "cloud").unwrap_err();
        assert!(
            format!("{err:#}").contains("no `static` route"),
            "got: {err:#}"
        );
    }

    // ── R561-F4: alias-tier registration ──
    use super::{plan_alias_claim, valid_subdomain_label, AliasTier};
    use std::collections::BTreeMap;

    #[test]
    fn label_validation_rules() {
        assert!(valid_subdomain_label("scrabcake"));
        assert!(valid_subdomain_label("my-repo-1"));
        assert!(!valid_subdomain_label("")); // empty
        assert!(!valid_subdomain_label("-lead")); // leading hyphen
        assert!(!valid_subdomain_label("trail-")); // trailing hyphen
        assert!(!valid_subdomain_label("Caps")); // uppercase
        assert!(!valid_subdomain_label("under_score")); // underscore
    }

    #[test]
    fn claim_builds_net_tier_manifest() {
        let dom = plan_alias_claim(
            AliasTier::Net,
            "scrabcake",
            "scrabcake/site",
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(dom.name, "scrabcake-net-yah-dev");
        assert_eq!(dom.domain, "scrabcake.net.yah.dev");
        assert_eq!(dom.cdn_bucket, "net-yah-dev");
        assert_eq!(dom.routes.len(), 1);
        assert!(
            matches!(&dom.routes[0].mode, RouteMode::Static { component } if component == "scrabcake/site")
        );
    }

    #[test]
    fn claim_uses_com_tier_zone_and_bucket() {
        let dom = plan_alias_claim(AliasTier::Com, "acme", "acme/site", &BTreeMap::new()).unwrap();
        assert_eq!(dom.domain, "acme.com.yah.dev");
        assert_eq!(dom.cdn_bucket, "com-yah-dev");
    }

    #[test]
    fn claim_bails_on_duplicate_host() {
        let existing: BTreeMap<String, DomainConfig> =
            [("scrabcake-net-yah-dev".to_string(), net_tier_manifest())]
                .into_iter()
                .collect();
        let err =
            plan_alias_claim(AliasTier::Net, "scrabcake", "scrabcake/site", &existing).unwrap_err();
        assert!(format!("{err:#}").contains("already"), "got: {err:#}");
    }

    #[test]
    fn claim_bails_on_invalid_label() {
        let err =
            plan_alias_claim(AliasTier::Net, "Bad_Name", "x/y", &BTreeMap::new()).unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid subdomain"),
            "got: {err:#}"
        );
    }

    // ── R859-F1: sovereign apex (front_door = "passway") ──
    //
    // Everything here is the pure half. The blast radius of this arm is LIVE
    // DNS on a public apex, so the decision logic is exercised offline in full
    // and `deploy_domain_passway` only executes the diff these produce.

    use super::{
        diff_apex_records, plan_domain_passway, plan_passway_apex, public_origins, ApexRecordDiff,
        DomainPasswayPlan, LiveApexRecord, PasswayOrigin, ResolvedOrigins,
    };
    use crate::config::{ConnectSpec, MachineConfig};
    use std::net::Ipv4Addr;

    /// Mirrors `.yah/domains/yah-dev.toml` — the only `front_door = "passway"`
    /// manifest in the camp today.
    fn passway_manifest() -> DomainConfig {
        DomainConfig {
            schema_version: 1,
            name: "yah-dev".into(),
            domain: "yah.dev".into(),
            front_door: FrontDoor::Passway,
            cdn_bucket: "yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
                headers: Default::default(),
                path: "/*".into(),
                mode: RouteMode::Static {
                    component: "yah-marketing/site".into(),
                },
            }],
        }
    }

    fn machine(name: &str, address: Option<&str>, taints: &[&str]) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "ovh".into(),
            location: None,
            server_type: None,
            hosts_mirrors: vec![],
            mesh_tags: vec![],
            region: None,
            zone: None,
            arch: None,
            bucket: None,
            vendor: None,
            nickname: None,
            legacy_hostkey_fingerprint: None,
            registration: Default::default(),
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: address.map(|a| ConnectSpec {
                address: a.into(),
                ssh: format!("root@{a}"),
                identity_file: "~/.ssh/yah".into(),
                yubaba_port: None,
                yubaba: None,
            }),
            allocatable: None,
            taints: taints.iter().map(|t| t.to_string()).collect(),
            sovereign_group: None,
            sovereign_role: None,
            ingress_floating_ip: None,
        }
    }

    /// The live fleet shape: us-east-001 and us-west-001 both carry the
    /// `public-ip` taint with a public address (machines/*.toml), a third box
    /// fronts internal hostnames over the mesh and must not reach the apex.
    fn fleet() -> Vec<MachineConfig> {
        vec![
            machine("us-east-001", Some("51.81.85.145"), &["public-ip"]),
            machine("us-west-001", Some("15.204.89.240"), &["public-ip"]),
            machine("us-west-002", Some("100.64.0.4"), &[]),
        ]
    }

    fn origins(names: &[&str]) -> ResolvedOrigins {
        origins_excluding(names, &[])
    }

    /// R859-F2: the same resolution with `down` confirmed dead — declared and
    /// resolvable, but held out of the published set.
    fn origins_excluding(names: &[&str], down: &[&str]) -> ResolvedOrigins {
        let fleet = fleet();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let down: Vec<String> = down.iter().map(|n| n.to_string()).collect();
        public_origins(&names, &fleet, &down).unwrap()
    }

    /// A plan whose origin set is COMPLETE — the clean-collation case.
    fn plan_of(names: &[&str]) -> DomainPasswayPlan {
        plan_domain_passway(&passway_manifest(), origins(names), true).unwrap()
    }

    /// The same plan, but built from a collation that reported problems, so an
    /// origin's absence cannot be read as a withdrawal.
    fn plan_of_incomplete(names: &[&str]) -> DomainPasswayPlan {
        plan_domain_passway(&passway_manifest(), origins(names), false).unwrap()
    }

    fn live(records: &[(&str, bool)]) -> Vec<LiveApexRecord> {
        records
            .iter()
            .map(|(content, proxied)| LiveApexRecord {
                content: (*content).into(),
                proxied: *proxied,
            })
            .collect()
    }

    #[test]
    fn public_origins_keeps_tainted_machines_and_skips_the_rest() {
        let got = origins(&["us-east-001", "us-west-001", "us-west-002"]);
        assert!(
            got.health_withdrawn.is_empty(),
            "no exclusions were passed, so nothing may be withheld"
        );
        assert_eq!(
            got.origins,
            vec![
                PasswayOrigin {
                    machine: "us-east-001".into(),
                    address: Ipv4Addr::new(51, 81, 85, 145),
                },
                PasswayOrigin {
                    machine: "us-west-001".into(),
                    address: Ipv4Addr::new(15, 204, 89, 240),
                },
            ],
            "an untainted mesh-only front door is not an apex origin"
        );
    }

    /// The publicness cross-check nothing did before R859-F1: the `public-ip`
    /// taint and `connect.address` are independent declarations, and a machine
    /// dialled over its tailnet address would otherwise publish `100.64.0.x`
    /// at a public apex and black-hole its share of the round-robin.
    #[test]
    fn public_origins_rejects_a_non_public_address_and_names_the_machine() {
        for bad in ["100.64.0.4", "10.0.0.7", "192.168.1.20", "127.0.0.1"] {
            let fleet = vec![machine("us-west-002", Some(bad), &["public-ip"])];
            let err = public_origins(&["us-west-002".to_string()], &fleet, &[]).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("us-west-002"), "{msg}");
            assert!(msg.contains(bad), "{msg}");
            assert!(msg.contains("public"), "{msg}");
        }
    }

    #[test]
    fn public_origins_rejects_an_unparseable_address_and_names_the_machine() {
        let fleet = vec![machine("us-east-001", Some("edge.example.net"), &["public-ip"])];
        let err = public_origins(&["us-east-001".to_string()], &fleet, &[]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("us-east-001"), "{msg}");
        assert!(msg.contains("not an IPv4 address"), "{msg}");
    }

    #[test]
    fn public_origins_rejects_a_tainted_machine_with_no_connect_block() {
        let fleet = vec![machine("us-east-001", None, &["public-ip"])];
        let err = public_origins(&["us-east-001".to_string()], &fleet, &[]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("us-east-001"), "{msg}");
        assert!(msg.contains("[connect]"), "{msg}");
    }

    #[test]
    fn public_origins_rejects_a_machine_with_no_toml() {
        let err = public_origins(&["ghost-001".to_string()], &fleet(), &[]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ghost-001"), "{msg}");
    }

    #[test]
    fn plan_sorts_and_dedups_origins_and_resolves_the_apex_zone() {
        let mut o = origins(&["us-west-001", "us-east-001"]);
        o.origins.push(o.origins[0].clone()); // same machine collated twice
        let plan = plan_domain_passway(&passway_manifest(), o, true).unwrap();
        assert_eq!(plan.zone, "yah.dev");
        assert_eq!(plan.name, "yah.dev");
        assert_eq!(
            plan.origins
                .iter()
                .map(|o| o.address.to_string())
                .collect::<Vec<_>>(),
            vec!["15.204.89.240", "51.81.85.145"],
        );
    }

    /// A camp may declare `front_door = "passway"` BEFORE the passway edge
    /// exists — the field is how you say which door you intend, and R859-F1
    /// made it the mechanism as well, so it gets written first. The noisetable
    /// camp is exactly this: `noisetable.com` declares `passway`, its only
    /// ingress edge is a `cloudflare-tunnel` on a different domain, and its
    /// apex is deliberately NXDOMAIN pending a node of its own (passway serves
    /// one cert per listener — R777).
    ///
    /// That must plan to `None`, never to an `Err`. The domain loop in `yah
    /// cloud apply` bails at the first domain failure without
    /// `--continue-on-error`, so an error here would take down the publish
    /// chain of every service in the camp over a door nobody has built yet.
    #[test]
    fn a_passway_domain_with_no_ingress_edge_plans_to_none_rather_than_erroring() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A workspace with a services tree but nothing fronting anything —
        // the shape of a camp whose door is declared but not stood up.
        std::fs::create_dir_all(root.join(".yah/services")).unwrap();

        let planned = plan_passway_apex(root, &passway_manifest())
            .expect("an undeclared door is not an error");
        assert!(
            planned.is_none(),
            "expected None (nothing to render), got {planned:?}"
        );
    }

    /// R870-B13, end to end: a camp that BORROWS another camp's fleet renders
    /// its sovereign apex from the owner's machine declaration.
    ///
    /// This is the ticket's defect in one test. The borrowing camp's own
    /// `.yah/infra/machines/` is empty — it declares one `[[source]]` link in
    /// `.yah/infra/sources.toml` and pins its front door by name. Before the
    /// fix, `plan_passway_apex` read a camp-local-only loader, so the pinned
    /// name resolved against an empty fleet and the render died with "has no
    /// .yah/infra/machines/*.toml — cannot resolve its public address" on a
    /// machine that was declared all along, one directory over.
    ///
    /// The camp-local control assertion is what makes this non-vacuous: the
    /// borrowing camp genuinely holds no copy of the inventory, so a pass here
    /// can only come from the link being followed.
    #[test]
    fn a_borrowing_camp_renders_its_apex_from_the_owners_machine_declaration() {
        let dir = tempfile::tempdir().unwrap();

        // The owner camp — the ONE copy of the inventory.
        let owner = dir.path().join("owner");
        std::fs::create_dir_all(owner.join(".yah/infra/machines")).unwrap();
        std::fs::write(
            owner.join(".yah/infra/machines/us-east-001.toml"),
            "name = \"us-east-001\"\nprovider = \"ovh\"\nmesh_tags = []\n\
             taints = [\"public-ip\"]\n\
             [connect]\naddress = \"51.81.85.145\"\nssh = \"root@51.81.85.145\"\n\
             identity_file = \"~/.ssh/yah\"\n",
        )
        .unwrap();

        // The borrowing camp: empty machines dir, one link, one pinned edge.
        let borrower = dir.path().join("borrower");
        std::fs::create_dir_all(borrower.join(".yah/infra/machines")).unwrap();
        std::fs::write(
            borrower.join(".yah/infra/sources.toml"),
            "schema_version = 1\n[[source]]\nowner = \"owner\"\nkind = \"path\"\n\
             path = \"../owner\"\nmode = \"read-only\"\n",
        )
        .unwrap();
        let svc = borrower.join(".yah/services/marketing");
        std::fs::create_dir_all(svc.join("mirrors")).unwrap();
        std::fs::write(
            svc.join("service.toml"),
            "schema_version = 1\nname = \"marketing\"\ndomain = \"yah.dev\"\n\
             [[components]]\nid = \"site\"\nkind = \"static-asset\"\n\
             path = \"marketing/site\"\nrole = \"static\"\n",
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/cloud.toml"),
            "schema_version = 1\nshape = \"single-machine\"\n\
             ingress = \"passway\"\ningress_machines = [\"us-east-001\"]\n\
             [providers.compute]\nuse = \"hetzner\"\nzone = \"yah.dev\"\n\
             port = 8080\nupstream_host = \"100.64.0.5\"\n",
        )
        .unwrap();

        // Control: the camp holds no machine declaration of its own.
        assert!(crate::validate::load_camp_local_machine_tomls(&borrower)
            .unwrap()
            .is_empty());

        let plan = plan_passway_apex(&borrower, &passway_manifest())
            .expect("a borrowed front-door machine must resolve")
            .expect("the passway edge collates, so this is not the no-door case");
        assert_eq!(
            plan.origins
                .iter()
                .map(|o| o.address.to_string())
                .collect::<Vec<_>>(),
            vec!["51.81.85.145".to_string()],
        );
    }

    /// The failure that remains a failure, with the diagnosis attached: a
    /// pinned machine no linked source supplies must still error — and the
    /// error must name the links that were consulted, since "no such machine"
    /// alone cannot tell an undeclared link from a broken one.
    #[test]
    fn an_unresolvable_front_door_names_the_links_that_were_consulted() {
        let dir = tempfile::tempdir().unwrap();
        let borrower = dir.path().join("borrower");
        std::fs::create_dir_all(borrower.join(".yah/infra/machines")).unwrap();
        std::fs::write(
            borrower.join(".yah/infra/sources.toml"),
            "schema_version = 1\n[[source]]\nowner = \"owner\"\nkind = \"path\"\n\
             path = \"../not-a-camp\"\n",
        )
        .unwrap();
        let svc = borrower.join(".yah/services/marketing");
        std::fs::create_dir_all(svc.join("mirrors")).unwrap();
        std::fs::write(
            svc.join("service.toml"),
            "schema_version = 1\nname = \"marketing\"\ndomain = \"yah.dev\"\n\
             [[components]]\nid = \"site\"\nkind = \"static-asset\"\n\
             path = \"marketing/site\"\nrole = \"static\"\n",
        )
        .unwrap();
        std::fs::write(
            svc.join("mirrors/cloud.toml"),
            "schema_version = 1\nshape = \"single-machine\"\n\
             ingress = \"passway\"\ningress_machines = [\"us-east-001\"]\n\
             [providers.compute]\nuse = \"hetzner\"\nzone = \"yah.dev\"\n\
             port = 8080\nupstream_host = \"100.64.0.5\"\n",
        )
        .unwrap();

        let err = plan_passway_apex(&borrower, &passway_manifest()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("us-east-001"), "{msg}");
        assert!(msg.contains("sources.toml"), "{msg}");
        assert!(msg.contains("owner"), "{msg}");
        assert!(msg.contains("ABSENT"), "{msg}");
    }

    /// The other side of that discriminator, and the reason it is drawn at the
    /// COLLATION rather than at the resolved-address set: a machine that IS
    /// declared as a front door but yields no public address is a
    /// misconfiguration of an intended door, and stays an error.
    #[test]
    fn a_declared_front_door_that_resolves_to_no_public_address_still_errors() {
        // Declared as a front door, but carries no `public-ip` taint — so the
        // taint filter empties the set even though the edge exists.
        let machines = vec![machine("us-east-001", Some("51.81.85.145"), &[])];
        let resolved = public_origins(&["us-east-001".to_string()], &machines, &[]).unwrap();
        let err = plan_domain_passway(&passway_manifest(), resolved, true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("empty apex"), "{msg}");
    }

    /// The live-DNS blast radius this arm exists to bound: an empty desired
    /// set is what the applier prunes against, so rendering it would withdraw
    /// every A record at the apex. Nothing about "no machine declared it"
    /// means "take the site down" — it must be an error, not a wipe.
    #[test]
    fn empty_origin_set_is_an_error_not_an_apex_wipe() {
        let err = plan_domain_passway(&passway_manifest(), ResolvedOrigins::default(), true).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("refusing to render an empty apex"), "{msg}");
        assert!(msg.contains("yah.dev"), "{msg}");
    }

    #[test]
    fn plan_bails_when_front_door_is_not_passway() {
        for door in [FrontDoor::BucketDirect, FrontDoor::Worker] {
            let mut dom = passway_manifest();
            dom.front_door = door;
            let err = plan_domain_passway(&dom, origins(&["us-east-001"]), true).unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("front_door"), "{msg}");
            assert!(msg.contains(door.as_str()), "{msg}");
        }
    }

    #[test]
    fn converged_apex_is_a_no_op() {
        let plan = plan_of(&["us-east-001", "us-west-001"]);
        let diff = diff_apex_records(
            &plan,
            &live(&[("51.81.85.145", false), ("15.204.89.240", false)]),
        );
        assert_eq!(diff, ApexRecordDiff::default());
        assert!(diff.is_converged());
    }

    #[test]
    fn adding_a_machine_yields_exactly_one_added_record_and_no_prune() {
        let plan = plan_of(&["us-east-001", "us-west-001"]);
        let diff = diff_apex_records(&plan, &live(&[("51.81.85.145", false)]));
        assert_eq!(diff.upsert, vec!["15.204.89.240".to_string()]);
        assert!(diff.prune.is_empty(), "{diff:?}");
    }

    #[test]
    fn removing_a_machine_yields_exactly_one_prune_and_leaves_the_survivor() {
        let plan = plan_of(&["us-east-001"]);
        let diff = diff_apex_records(
            &plan,
            &live(&[("51.81.85.145", false), ("15.204.89.240", false)]),
        );
        assert_eq!(diff.prune, vec!["15.204.89.240".to_string()]);
        assert!(
            diff.upsert.is_empty(),
            "the survivor is already correct: {diff:?}"
        );
    }

    /// `scripts/cf-apex-mode.sh orange` is break-glass; the manifest declares
    /// DNS-only. A proxied record carrying a desired address is therefore
    /// drift, and re-upserting it (`proxied = false`) is the convergence.
    #[test]
    fn a_proxied_record_at_a_desired_address_is_rewritten_not_left_alone() {
        let plan = plan_of(&["us-east-001"]);
        let diff = diff_apex_records(&plan, &live(&[("51.81.85.145", true)]));
        assert_eq!(diff.upsert, vec!["51.81.85.145".to_string()]);
        assert!(
            diff.prune.is_empty(),
            "the address is declared — it must not be pruned: {diff:?}"
        );
    }

    /// **Fail-closed on withdrawal.** `collate_workspace_ingress` returns `Ok`
    /// while SKIPPING an edge whose declaration fails to plan, so a passway
    /// edge with a config typo silently drops its machine from `front_doors` —
    /// which, from inside the plan, is indistinguishable from the operator
    /// withdrawing that node. Without this gate a typo would render as a DNS
    /// withdrawal and take that origin offline. Upserts must still run: an
    /// unrelated service's broken declaration cannot be allowed to block
    /// growing the fleet, and an upsert can never make the apex worse.
    #[test]
    fn an_incomplete_collation_upserts_but_withholds_every_prune() {
        // us-west-001 is missing from the front-door set, and the collation
        // reported problems — so its absence is not trustworthy evidence of a
        // withdrawal. us-east-001 is newly declared and must still be written.
        let plan = plan_of_incomplete(&["us-east-001"]);
        let diff = diff_apex_records(&plan, &live(&[("15.204.89.240", false)]));

        assert_eq!(
            diff.upsert,
            vec!["51.81.85.145".to_string()],
            "additions must still land through a dirty collation"
        );
        assert!(
            diff.prune.is_empty(),
            "a live record must never be withdrawn on an incomplete collation: {diff:?}"
        );
        assert_eq!(
            diff.withheld_prune,
            vec!["15.204.89.240".to_string()],
            "the withheld record is reported so the applier can name it"
        );

        // Same inputs, clean collation: the prune is real. This is the
        // control that proves the gate is what changed the outcome.
        let trusted = plan_of(&["us-east-001"]);
        let diff = diff_apex_records(&trusted, &live(&[("15.204.89.240", false)]));
        assert_eq!(diff.prune, vec!["15.204.89.240".to_string()]);
        assert!(diff.withheld_prune.is_empty(), "{diff:?}");
    }

    /// The empty-set guard stays AHEAD of the incompleteness gate: an empty
    /// origin set is unusable whether or not the collation was clean, so it
    /// remains the louder failure rather than degrading into a silent
    /// everything-withheld apply.
    #[test]
    fn empty_origin_set_still_errors_on_an_incomplete_collation() {
        let err = plan_domain_passway(&passway_manifest(), ResolvedOrigins::default(), false).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to render an empty apex"),
            "got: {err:#}"
        );
    }

    // ── R859-F2: health-excluded origins ──────────────────────────────────

    /// The exclusion happens after full resolution, and reports what it held
    /// back rather than dropping it silently — `health_withdrawn` is what makes
    /// "declared but dead" distinguishable from "never declared" downstream.
    #[test]
    fn a_confirmed_down_machine_is_resolved_then_withheld_not_dropped() {
        let got = origins_excluding(&["us-east-001", "us-west-001"], &["us-east-001"]);
        assert_eq!(
            got.origins,
            vec![PasswayOrigin {
                machine: "us-west-001".into(),
                address: Ipv4Addr::new(15, 204, 89, 240),
            }]
        );
        assert_eq!(
            got.health_withdrawn,
            vec![PasswayOrigin {
                machine: "us-east-001".into(),
                address: Ipv4Addr::new(51, 81, 85, 145),
            }],
            "a withheld origin must still be reported, with the address it would have published"
        );
    }

    /// An exclusion naming a machine that fronts nothing is not an error. The
    /// caller's liveness view covers the whole fleet and most of it never
    /// fronts anything, so requiring the sets to line up would make every
    /// unrelated node failure an apex-render failure.
    #[test]
    fn excluding_a_machine_that_fronts_nothing_is_a_no_op() {
        let got = origins_excluding(&["us-east-001"], &["us-west-001", "ghost-001"]);
        assert_eq!(got.origins.len(), 1);
        assert!(got.health_withdrawn.is_empty());
    }

    /// The catastrophic case, and the reason the empty-set guard is checked
    /// against the *survivors*: "every front door is down" must not render as
    /// "withdraw every A record". A dead origin still in DNS is a partial
    /// outage; an empty apex is a total one.
    #[test]
    fn excluding_every_origin_is_an_error_not_an_apex_wipe() {
        let resolved = origins_excluding(
            &["us-east-001", "us-west-001"],
            &["us-east-001", "us-west-001"],
        );
        assert_eq!(resolved.health_withdrawn.len(), 2);
        let err = plan_domain_passway(&passway_manifest(), resolved, true).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to render an empty apex"),
            "got: {err:#}"
        );
    }

    /// Two machines can share one address (a floating IP mid-move, or two edges
    /// collated onto one box). Losing one of them must not withdraw a record
    /// the other still answers on.
    #[test]
    fn an_address_a_live_origin_still_serves_is_not_withdrawn() {
        let fleet = vec![
            machine("us-east-001", Some("51.81.85.145"), &["public-ip"]),
            machine("us-east-002", Some("51.81.85.145"), &["public-ip"]),
        ];
        let resolved = public_origins(
            &["us-east-001".to_string(), "us-east-002".to_string()],
            &fleet,
            &["us-east-001".to_string()],
        )
        .unwrap();
        let plan = plan_domain_passway(&passway_manifest(), resolved, true).unwrap();
        assert_eq!(
            plan.origins
                .iter()
                .map(|o| o.address.to_string())
                .collect::<Vec<_>>(),
            vec!["51.81.85.145"]
        );
        assert!(
            plan.health_withdrawn.is_empty(),
            "us-east-002 still answers on that address, so it must not be pruned"
        );
    }

    /// **The cross-product.** `origins_complete` and `health_withdrawn` are two
    /// different facts, and the bottom-right cell is the whole point of R859-F2:
    /// an unrelated service's broken declaration must not veto a withdrawal
    /// resting on a box we watched go down.
    #[test]
    fn health_withdrawal_and_declaration_completeness_are_independent() {
        let live = live(&[("51.81.85.145", false), ("15.204.89.240", false)]);

        // complete + healthy: an ordinary withdrawal from a trusted declaration.
        let complete_healthy = plan_domain_passway(
            &passway_manifest(),
            origins(&["us-west-001"]),
            true,
        )
        .unwrap();
        let d = diff_apex_records(&complete_healthy, &live);
        assert_eq!(d.prune, vec!["51.81.85.145"]);
        assert!(d.withheld_prune.is_empty());

        // complete + down: the same prune, now on health grounds.
        let complete_down = plan_domain_passway(
            &passway_manifest(),
            origins_excluding(&["us-east-001", "us-west-001"], &["us-east-001"]),
            true,
        )
        .unwrap();
        let d = diff_apex_records(&complete_down, &live);
        assert_eq!(d.prune, vec!["51.81.85.145"]);
        assert!(d.withheld_prune.is_empty());

        // incomplete + healthy: might be a withdrawal, might be a typo — withheld.
        let incomplete_healthy = plan_domain_passway(
            &passway_manifest(),
            origins(&["us-west-001"]),
            false,
        )
        .unwrap();
        let d = diff_apex_records(&incomplete_healthy, &live);
        assert!(
            d.prune.is_empty(),
            "an absence under an incomplete collation must never prune"
        );
        assert_eq!(d.withheld_prune, vec!["51.81.85.145"]);

        // incomplete + down: PRUNED ANYWAY. We saw this machine declared and we
        // saw it die; the incompleteness is about a different declaration.
        let incomplete_down = plan_domain_passway(
            &passway_manifest(),
            origins_excluding(&["us-east-001", "us-west-001"], &["us-east-001"]),
            false,
        )
        .unwrap();
        let d = diff_apex_records(&incomplete_down, &live);
        assert_eq!(
            d.prune,
            vec!["51.81.85.145"],
            "a health withdrawal rests on a positive observation, not on an absence, so \
             origins_complete = false must not suppress it"
        );
        assert!(d.withheld_prune.is_empty());
    }

    /// The two reasons for a prune coexist in one diff without merging: under an
    /// incomplete collation, the health-excluded address is pruned and the
    /// merely-absent one is still withheld.
    #[test]
    fn an_incomplete_collation_prunes_only_the_health_withdrawn_surplus() {
        let plan = plan_domain_passway(
            &passway_manifest(),
            origins_excluding(&["us-east-001", "us-west-001"], &["us-east-001"]),
            false,
        )
        .unwrap();
        let d = diff_apex_records(
            &plan,
            &live(&[
                ("51.81.85.145", false), // declared + confirmed down -> prune
                ("15.204.89.240", false), // the surviving origin -> kept
                ("203.0.113.9", false),  // never declared at all -> withheld
            ]),
        );
        assert_eq!(d.prune, vec!["51.81.85.145"]);
        assert_eq!(d.withheld_prune, vec!["203.0.113.9"]);
        assert!(d.upsert.is_empty());
    }

    /// A withheld prune is not convergence — it is a write the applier
    /// declined — but it is also not a write, so `is_converged` stays false
    /// only when there is something to actually do.
    #[test]
    fn a_withheld_prune_alone_leaves_nothing_to_write() {
        let plan = plan_of_incomplete(&["us-east-001"]);
        let diff = diff_apex_records(
            &plan,
            &live(&[("51.81.85.145", false), ("15.204.89.240", false)]),
        );
        assert!(diff.upsert.is_empty(), "{diff:?}");
        assert!(diff.prune.is_empty(), "{diff:?}");
        assert!(diff.is_converged(), "no write to make: {diff:?}");
        assert_eq!(diff.withheld_prune, vec!["15.204.89.240".to_string()]);
    }

    /// Ordering contract (`cf-apex-mode.sh:245-246,287-288`): the applier
    /// writes `upsert` before `prune`, so a full origin swap never leaves the
    /// apex without a routing record.
    #[test]
    fn a_full_origin_swap_writes_the_new_record_before_pruning_the_old() {
        let plan = plan_of(&["us-west-001"]);
        let diff = diff_apex_records(&plan, &live(&[("51.81.85.145", false)]));
        assert_eq!(diff.upsert, vec!["15.204.89.240".to_string()]);
        assert_eq!(diff.prune, vec!["51.81.85.145".to_string()]);
        assert!(!diff.is_converged());
    }
}
