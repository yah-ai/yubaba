//! Domain-level reconciler — `.yah/domains/*.toml` → live Cloudflare state.
//!
//! Today's only shape is the **R2 custom-domain** binding: a domain whose
//! `cdn_bucket` field names an R2 bucket and which has no `[[routes]]`.
//! Cloudflare's R2 Custom Domains API binds the hostname to the bucket and
//! writes the CNAME into the parent zone automatically when the zone lives
//! on the same account — no DNS-side call is needed here.
//!
//! Worker-routed domains (e.g. `yah-dev.toml`, `app-yah-dev.toml`, which
//! carry `[[routes]]`) are out of scope for this module; they get DNS +
//! route management through the Worker reconciler.

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::CloudflareClient;

/// Bind `domain` as a custom domain on `bucket_name`. Idempotent — does
/// nothing when the binding is already present, regardless of `enabled`
/// state (CF reflects newly-added bindings as `enabled: true` immediately;
/// disabling is an explicit dashboard action we don't undo here).
///
/// Resolves the Cloudflare API token from the `cloudflare-api-token`
/// keystore slot (or `CLOUDFLARE_API_TOKEN` env). Mirrors the list-first
/// pattern of `static_asset::ensure_r2_bucket` so the apply loop is safe
/// to re-run.
///
/// Required token scopes: `Workers R2 Storage: Edit` and `Zone: Read`
/// (the latter because the API requires the zone id of the parent zone —
/// CF writes the CNAME there). The caller does NOT need `DNS: Edit`; CF
/// provisions the record itself when the binding is created.
pub async fn ensure_r2_custom_domain(
    account_id: &str,
    bucket_name: &str,
    domain: &str,
) -> Result<()> {
    let api_token = fob::get_or_env("cloudflare-api-token", "CLOUDFLARE_API_TOKEN")
        .context("resolving cloudflare-api-token")?
        .context(
            "cloudflare-api-token not found — set via `yah keys set cloudflare-api-token` \
             or export CLOUDFLARE_API_TOKEN",
        )?;
    let cf = CloudflareClient::new(api_token);
    let existing = cf
        .list_r2_custom_domains(account_id, bucket_name)
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
    cf.add_r2_custom_domain(account_id, bucket_name, domain, &zone_id)
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

use crate::config::{DomainConfig, DomainRoute, RouteMode};
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
fn static_worker_bindings(asset_origin: &str) -> Vec<(String, String)> {
    vec![
        ("ASSET_ORIGIN".to_string(), asset_origin.to_string()),
        ("UPLOAD_ORIGIN".to_string(), String::new()),
        ("WORKER_MODE".to_string(), "static".to_string()),
        ("SSR_ORIGIN".to_string(), String::new()),
        ("SSR_PREFIXES".to_string(), "[]".to_string()),
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
        bindings: static_worker_bindings(&asset_origin),
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
pub async fn deploy_domain_worker(account_id: &str, plan: &DomainWorkerPlan) -> Result<()> {
    let api_token = fob::get_or_env("cloudflare-api-token", "CLOUDFLARE_API_TOKEN")
        .context("resolving cloudflare-api-token")?
        .context(
            "cloudflare-api-token not found — set via `yah keys set cloudflare-api-token` \
             or export CLOUDFLARE_API_TOKEN",
        )?;
    let cf = CloudflareClient::new(api_token);

    let worker_bindings: Vec<WorkerBinding<'_>> = plan
        .bindings
        .iter()
        .map(|(k, v)| WorkerBinding::PlainText {
            name: k.as_str(),
            text: v.as_str(),
        })
        .collect();

    cf.deploy_worker_script(
        account_id,
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
    cf.upsert_worker_custom_domain(account_id, &zone_id, &plan.custom_domain, &plan.worker_name)
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
        cdn_bucket: tier.bucket().to_string(),
        worker_bundle_path: None,
        routes: vec![DomainRoute {
            path: "/*".into(),
            mode: RouteMode::Static {
                component: component.to_string(),
            },
        }],
    })
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
    use crate::config::{DomainConfig, DomainRoute, RouteMode};

    fn net_tier_manifest() -> DomainConfig {
        // Mirrors .yah/domains/scrabcake-net-yah-dev.toml.
        DomainConfig {
            schema_version: 1,
            name: "scrabcake-net-yah-dev".into(),
            domain: "scrabcake.net.yah.dev".into(),
            cdn_bucket: "net-yah-dev".into(),
            worker_bundle_path: None,
            routes: vec![DomainRoute {
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
                ],
            }
        );
    }

    #[test]
    fn plan_trims_trailing_slash_on_cdn_base() {
        let plan =
            plan_domain_worker(&net_tier_manifest(), "https://cdn.net.yah.dev/", "cloud").unwrap();
        assert_eq!(plan.asset_origin, "https://cdn.net.yah.dev/scrabcake/cloud");
    }

    #[test]
    fn plan_bails_when_no_static_route() {
        let mut dom = net_tier_manifest();
        dom.routes = vec![DomainRoute {
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
}
