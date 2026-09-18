//! The compiled route table (R898-F1 / W348 §2.2) — ONE ordered artifact per
//! domain, rendered to both front doors.
//!
//! ## What this is, and what it replaces
//!
//! `DomainConfig.routes` is the declaration; this module is the compilation of
//! that declaration into the thing a door can execute: `{path, mode, resolved
//! origin, headers, auth}` per entry, in manifest order. It is the widening of
//! R746/R749-F3's `route_headers_json`, which compiled the same table down to
//! its header column and is live on yah.dev today (`x-route-header-probe`).
//!
//! **One producer, two renderers** is the whole point. A per-path capability
//! built into one door has to be built a second time the moment the domain
//! flips `front_door`, and it does not merely cost twice — it *evaporates*, as
//! `/api/releases` did when yah.dev went grey and `MESOFACT_BACKEND_ORIGIN`
//! stopped executing with nothing anywhere reporting it (W348 §0.3, §2.3).
//!
//! ## The resolved origin is the only genuinely new datum
//!
//! Everything else an entry carries is already in the manifest. The origin is
//! not, and it is **placement-time**:
//!
//! | mode | resolves to | by |
//! |---|---|---|
//! | `static` | the component's asset origin (`<cdn_base>/<service>/<env>`) | [`CdnPlacement::asset_origin`] |
//! | `static` + `bucket` | the bucket's Worker R2 binding name — no placement | [`r2_binding_name`] |
//! | `backend` | the deployed unit's address, keyed by its mesh identity | [`inner_door::component_workload_ident`](crate::inner_door::component_workload_ident) |
//! | `redirect` | nothing — it carries its own target + status | — |
//!
//! The declared `origin` field on [`RouteMode::Backend`] is deliberately NOT
//! the answer: it is the Worker arm's `fetch()` target and nothing reads it
//! under passway (`.yah/domains/api-noisetable-com.toml` says so in its own
//! words, in the noisetable camp). A table that echoed it would be wrong on the
//! door that actually serves production.
//!
//! So placement arrives as a [`RoutePlacement`] — the same shape
//! [`InnerDoorPlan::routes_file`](crate::inner_door::InnerDoorPlan::routes_file)
//! already uses for upstream addresses, for the same reason: which node a unit
//! landed on is not config. An unresolved origin is **refused**, never skipped
//! — a dropped entry does not 503, it falls through to a shorter match (the
//! catch-all, usually) and serves the wrong thing with a 200.
//!
//! ## Ordering and matching are pinned, not chosen here
//!
//! Manifest order, **first match wins, no merging across rules** — R746 pinned
//! it in TS (`applyRouteHeaders`, `oss/mesofact/packages/mesofact-edge/src/router.ts`)
//! and R749-F3 carried it into Rust (`mesofact::route_headers`). One path has
//! one entry, decided where the route was decided. The manifests already
//! document it as their contract: `noisetable-com.toml` puts `/app/*` above
//! `/*` precisely because of it.
//!
//! [`matches_route_pattern`] is segment-aware for the same reason both of those
//! are: a bare `starts_with` routes `/application` to the `/app` entry. It is a
//! third copy of a two-sided wire format rather than a call into either — the
//! Worker is TypeScript and `mesofact` is a separately-released crate in
//! another workspace that `cloud` does not depend on — and it is handled the
//! way this repo already handles that risk for passway's
//! `path_route::mount_from_component`: one producer, and a test pinning the
//! shared cases.
//!
//! ## Why the header projection is still the wire value
//!
//! [`RouteTable::headers_json`] is the header column of this same table, byte-
//! identical to what `DomainConfig::route_headers_json` emits — and that string,
//! not the full table, is still what `ROUTE_HEADERS` / `MESOFACT_ROUTE_HEADERS`
//! carry. Widening those bindings is R898-F2 (passway) and R898-F3 (Worker).
//! Shipping the wide table into them here would change deployed behaviour
//! before either consumer can read it: every headerless route becomes a table
//! entry, so `app.yah.dev`, `chat.yah.dev` and `scrabcake.net.yah.dev` — each a
//! single route declaring no headers, each `"[]"` today — would start setting
//! `MESOFACT_ROUTE_HEADERS` on their deploys.
//!
//! ## A backend entry carries its prefix rewrite (R898-F3)
//!
//! The two backend seams that exist today are **not** identity proxies:
//! `/api/issues/42` reaches the issue tracker as `/issues/42`, and
//! `/api/releases/v1.2.3` reaches the almanac as `/releases/v1.2.3`. Those
//! rewrites lived inside the Worker's two hardcoded `if` blocks (R455-T4),
//! which is precisely what R898-F3 deleted — so an origin-only entry would have
//! silently started proxying `/api/issues` to `<origin>/api/issues` and changed
//! the upstream contract with no diff naming it.
//!
//! So [`ResolvedRouteMode::Backend`] carries an optional [`RouteRewrite`]:
//! `{from, to}`, the public prefix the matched path carries and what it becomes
//! at the origin. It is route DATA, declared as `origin_path` on
//! [`RouteMode::Backend`] — not an escape hatch, and not a per-door special
//! case. The alternative was restating the two routes so the public path equals
//! the origin path, which this repo cannot do: it does not own either upstream's
//! path layout, and both are live contracts.
//!
//! ## R560-F13 folds in here
//!
//! "One Worker domain fronting several R2 buckets" is this table restricted to
//! `static` entries whose sources differ. Same artifact, narrower slice — W279
//! Gap C predicted the fold ("path-prefix -> bucket is just a route list").
//!
//! A bucket route does NOT resolve to an HTTP origin, and that is the one
//! deliberate asymmetry: the buckets it exists for (noisetable-releases) have
//! no public hostname to fetch, and a bucket root is not a placement fact
//! anyway — the manifest names it outright. So [`RouteMode::StaticBucket`]
//! compiles to [`ResolvedRouteMode::StaticBucket`], carrying the Worker binding
//! it reads through ([`r2_binding_name`]), and the Worker's binding set gains
//! one R2 bucket binding per distinct bucket ([`r2_bucket_bindings`]), derived
//! from the same entries the table ships so the two cannot name different
//! bindings. The key is the request path minus its leading slash, unchanged:
//! xlb derives a blob's key from the URL path it serves at.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::Serialize;

use crate::config::{
    domain_serving_service, load_domains, split_component_ref, DomainConfig, DomainRoute, RouteMode,
};
use crate::inner_door::component_workload_ident;

/// The placement-time facts a declared route cannot answer about itself.
///
/// Two separate methods rather than one origin lookup because the two
/// resolutions have nothing in common: a static route's origin is a published
/// *storage* prefix that exists before anything is deployed, and a backend
/// route's is the address of a running unit. Collapsing them would force every
/// implementor to re-derive the mode from the component ref.
///
/// `None` from either is a refused compile ([`DomainConfig::route_table`]), not
/// a skipped entry.
pub trait RoutePlacement {
    /// Where a `static` route's component publishes its bytes.
    ///
    /// `path` is the route's own pattern, present for the multi-bucket case
    /// (R560-F13) where the prefix, not the component, picks the origin.
    fn asset_origin(&self, component: &str, path: &str) -> Option<String>;

    /// Where a `backend` route's deployed unit is reachable.
    fn backend_origin(&self, component: &str, path: &str) -> Option<String>;

    /// Path prefixes the door fronting this domain requires a bearer on —
    /// `PasswayAuth::require_prefixes`, verbatim. Default: an anonymous door,
    /// which is every Worker-fronted domain (the Worker arm has no bearer auth
    /// at all).
    fn auth_required_prefixes(&self) -> &[String] {
        &[]
    }
}

/// The origin resolution that exists today: the CDN prefix for static routes,
/// and a mesh-identity-keyed address map for backend ones.
///
/// `addresses` is keyed by **mesh identity**, not by component ref, so it takes
/// [`InnerDoorPlan::resolve_addresses`](crate::inner_door::InnerDoorPlan::resolve_addresses)'
/// output shape directly and the identity derivation stays in the one place
/// that owns it ([`component_workload_ident`]).
#[derive(Debug, Clone, Default)]
pub struct CdnPlacement {
    /// The tier's CDN origin, e.g. `https://cdn.yah.dev`. Trailing slash
    /// tolerated.
    pub cdn_base: String,
    /// Mirror env the publisher wrote under, e.g. `prod`.
    pub env: String,
    /// `mesh ident -> host:port` for every deployed unit a backend route names.
    pub addresses: BTreeMap<String, String>,
    /// `PasswayAuth::require_prefixes` of the door fronting this domain.
    pub auth_required_prefixes: Vec<String>,
}

impl RoutePlacement for CdnPlacement {
    /// `<cdn_base>/<service>/<env>` — the same string
    /// `reconciler::domain::plan_domain_worker` computes and the same one a
    /// mirror's `providers.static.asset_origin` carries. The component's
    /// `mount` is deliberately absent: the front door fetches
    /// `${ASSET_ORIGIN}/<request path>`, so the mount is already in the path
    /// (see `mesofact_static::publish_prefix`).
    fn asset_origin(&self, component: &str, _path: &str) -> Option<String> {
        cdn_asset_origin(&self.cdn_base, &self.env, component)
    }

    fn backend_origin(&self, component: &str, _path: &str) -> Option<String> {
        let (service, id) = split_component_ref(component)?;
        self.addresses
            .get(&component_workload_ident(service, id))
            .map(|addr| format!("http://{addr}"))
    }

    fn auth_required_prefixes(&self) -> &[String] {
        &self.auth_required_prefixes
    }
}

/// The Worker binding name a bucket route reads its bucket through:
/// `noisetable-releases` → `R2_NOISETABLE_RELEASES`.
///
/// Deterministic, so the table entry and the binding list agree without either
/// carrying a lookup, and collision-free: an R2 bucket name is lowercase
/// letters, digits and hyphens only (refused otherwise at parse time), so
/// upper-casing and `-` → `_` is injective. The `R2_` prefix keeps every such
/// binding clear of the plain-text ones (`ASSET_ORIGIN`, `ROUTE_TABLE`, …).
pub fn r2_binding_name(bucket: &str) -> String {
    format!("R2_{}", bucket.to_ascii_uppercase().replace('-', "_"))
}

/// One R2 bucket binding per DISTINCT bucket the entries read, in first-use
/// (manifest) order: `(binding name, bucket name)`.
///
/// Derived from compiled entries rather than from the declaration so the
/// binding list a Worker deploys with is a function of the very table it ships
/// — an entry naming a binding the upload did not create would 502 at the door.
pub fn r2_bucket_bindings<'a>(
    entries: impl IntoIterator<Item = &'a RouteTableEntry>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in entries {
        if let ResolvedRouteMode::StaticBucket { bucket, binding } = &entry.mode {
            if !out.iter().any(|(b, _)| b == binding) {
                out.push((binding.clone(), bucket.clone()));
            }
        }
    }
    out
}

/// `<cdn_base>/<service>/<env>` — where a static component's published bytes
/// land, and the one spelling of that string.
///
/// A free function because it has two callers that must not drift:
/// [`CdnPlacement`] (the production door) and [`WorkerAssets::PerComponent`]
/// (the alias tier's Worker). `None` on a component ref that is not
/// `<service>/<component-id>`, which [`DomainConfig::route_table`] turns into a
/// refused compile naming the route.
pub(crate) fn cdn_asset_origin(cdn_base: &str, env: &str, component: &str) -> Option<String> {
    let (service, _) = split_component_ref(component)?;
    Some(format!("{}/{}/{}", cdn_base.trim_end_matches('/'), service, env))
}

/// How the Worker arm resolves a **static** route's origin (R898-T4).
///
/// Two shapes because the Worker arm is configured from two sources that
/// differ in exactly this: a mirror's static slot carries ONE deployed
/// `asset_origin` field, while a domain manifest carries a component ref per
/// route. Collapsing both to the deployed string is what made a second static
/// route meaningless — every entry would resolve to the same origin, which is
/// `plan_domain_worker`'s `find_map`-the-first defect wearing a table.
#[derive(Debug, Clone, Copy)]
pub enum WorkerAssets<'a> {
    /// Every static route serves from this one origin — the mirror-driven
    /// path, where the slot's `asset_origin` field IS the answer.
    Deployed(&'a str),
    /// Each static route serves from its own component's published prefix.
    /// The alias tier (R561-F3), and the several-buckets-behind-one-domain
    /// case R560-F13 asked for: the routes name different services, so they
    /// resolve to different origins.
    PerComponent {
        /// The tier's CDN origin, e.g. `https://cdn.net.yah.dev`.
        cdn_base: &'a str,
        /// Mirror env the publisher wrote under, e.g. `prod`.
        env: &'a str,
    },
    /// No CDN tier is known — a manifest-only Worker deployed by the domain
    /// pass (R560-F13). A component static route has no origin under this and
    /// the compile refuses it naming the route; bucket, backend and redirect
    /// routes need no asset placement and compile as usual.
    Unplaced,
}

impl WorkerAssets<'_> {
    /// The `ASSET_ORIGIN` binding value: where a path that NO table entry
    /// claims is fetched from.
    ///
    /// For [`Self::Deployed`] that is the deployed origin, domain or no domain.
    /// For [`Self::PerComponent`] it is the FIRST static route's origin — not
    /// because first-wins is back, but because `ASSET_ORIGIN` is a single
    /// binding and a domain with a static catch-all resolves it to the same
    /// string either way. Every static route still gets its own entry in the
    /// table, which is what the door actually matches on.
    ///
    /// `None` means no path falls through to an HTTP asset origin: no domain,
    /// no component static route (bucket routes read through R2 bindings, not
    /// an origin), a static route whose component ref is malformed, or
    /// [`Self::Unplaced`].
    ///
    /// [`Self::Deployed`] is returned VERBATIM, trailing slash and all, while
    /// [`RoutePlacement::asset_origin`] trims it for the table. That asymmetry
    /// is deliberate and load-bearing: the `ASSET_ORIGIN` binding is a live
    /// deployed value read off a mirror's static slot, and R898-T4 is not the
    /// change that quietly renormalizes it under every Worker on the fleet.
    pub fn fallback_origin(&self, domain: Option<&DomainConfig>) -> Option<String> {
        match self {
            Self::Deployed(origin) => Some((*origin).to_string()),
            Self::PerComponent { cdn_base, env } => {
                domain?.routes.iter().find_map(|r| match &r.mode {
                    RouteMode::Static { component } => cdn_asset_origin(cdn_base, env, component),
                    _ => None,
                })
            }
            Self::Unplaced => None,
        }
    }
}

/// The Worker arm's placement (R898-F3).
///
/// The Cloudflare Worker is the one door for which the manifest's **declared**
/// `origin` is the right answer — `api-noisetable-com.toml`'s own words: "this
/// field is the Worker arm's `fetch()` target and nothing else reads it". So
/// `backend_origin` reads the declaration back off the route it is resolving,
/// while [`CdnPlacement`] resolves the same entry to a mesh address for the
/// door that serves production.
///
/// The static half is [`WorkerAssets`] — see there for why it is not simply the
/// deployed `ASSET_ORIGIN` string.
pub struct WorkerPlacement<'a> {
    /// How this Worker's static routes resolve their origins.
    pub assets: WorkerAssets<'a>,
    /// The domain being compiled — read back for the declared backend origin.
    pub domain: &'a DomainConfig,
}

impl RoutePlacement for WorkerPlacement<'_> {
    fn asset_origin(&self, component: &str, _path: &str) -> Option<String> {
        match self.assets {
            WorkerAssets::Deployed(origin) => Some(origin.trim_end_matches('/').to_string()),
            WorkerAssets::PerComponent { cdn_base, env } => {
                cdn_asset_origin(cdn_base, env, component)
            }
            WorkerAssets::Unplaced => None,
        }
    }

    fn backend_origin(&self, _component: &str, path: &str) -> Option<String> {
        // Found by EXACT pattern, not by [`DomainConfig::route_for_path`]: the
        // compiler hands us the route's own `path`, and a catch-all declared
        // above it would match that string and answer for the wrong route.
        let declared = self.domain.routes.iter().find(|r| r.path == path)?;
        match &declared.mode {
            RouteMode::Backend { origin, .. } if !origin.is_empty() => {
                Some(origin.trim_end_matches('/').to_string())
            }
            _ => None,
        }
    }
}

/// Whether a path reaching this entry has to carry a bearer.
///
/// Not new vocabulary: it is `PasswayAuth::require_prefixes` — the door's
/// allowlist of prefixes requiring a bearer — evaluated per route, so the UX
/// and the doors read one answer instead of each re-deriving it (W348 §4.2,
/// §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteAuth {
    /// No prefix the door protects covers this route.
    Anonymous,
    /// Every request this route matches requires a bearer.
    Bearer,
}

/// The prefix swap a backend route performs on its way to the origin.
///
/// Both halves are explicit rather than "strip `from`, prepend `to`" implied by
/// the route path alone: the door applying this is a TypeScript Worker that
/// must not have to re-derive a prefix from a pattern, and a rewrite that only
/// carried its replacement would be unreadable in the wire value a deploy logs.
///
/// `from` is the matched route's own prefix (`"/api/issues*"` → `"/api/issues"`);
/// `to` is what the origin serves it at (`"/issues"`). Applied as
/// `to + path[from.len()..]`, so `/api/issues/42` → `/issues/42` and the bare
/// `/api/issues` → `/issues`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteRewrite {
    /// The public prefix, as matched.
    pub from: String,
    /// What that prefix becomes at the origin.
    pub to: String,
}

/// Compile a declared `origin_path` into a [`RouteRewrite`] against the route's
/// own path pattern.
///
/// `None` when nothing was declared, and also when the declaration is the
/// identity — an entry saying "rewrite `/api` to `/api`" is noise on the wire
/// and a needless branch at the door.
fn route_rewrite(route_path: &str, origin_path: Option<&String>) -> Option<RouteRewrite> {
    let to = origin_path?;
    let from = route_path.strip_suffix('*').unwrap_or(route_path);
    let from = from.trim_end_matches('/');
    let to = to.trim_end_matches('/');
    if from == to {
        return None;
    }
    Some(RouteRewrite {
        from: from.to_string(),
        to: to.to_string(),
    })
}

/// A compiled entry's body — the declared [`RouteMode`] with its origin
/// **resolved**.
///
/// The origin lives inside the variant rather than beside it as an
/// `Option<String>`, so "a static entry with no origin" has no spelling and
/// "a redirect with one" has none either. Same move [`DeployTier`] makes for
/// the deploy tiers: the contradictory state is unrepresentable rather than
/// refused.
///
/// [`DeployTier`]: crate::config::DeployTier
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum ResolvedRouteMode {
    Static {
        /// Component reference `"<service>/<component-id>"`, as declared.
        component: String,
        /// Where the door fetches this route's bytes from.
        origin: String,
    },
    /// A bucket-root static route (R560-F13). Same `mode = "static"` on the
    /// wire — the door tells the two apart by `binding` — because both are
    /// "serve the bytes at this key", and only the reader differs.
    #[serde(rename = "static")]
    StaticBucket {
        /// The R2 bucket, as declared.
        bucket: String,
        /// The Worker binding the door reads it through,
        /// [`r2_binding_name`]`(bucket)`. The key is the request path minus its
        /// leading slash, unchanged.
        binding: String,
    },
    Backend {
        component: String,
        /// Where the door proxies this route to — the *deployed unit's*
        /// address, not the manifest's `origin` field.
        origin: String,
        /// How the matched path is rewritten before it reaches `origin`.
        /// `None` is an identity proxy (the common case).
        #[serde(skip_serializing_if = "Option::is_none")]
        rewrite: Option<RouteRewrite>,
    },
    Redirect {
        target: String,
        status: u16,
    },
}

/// One entry of the compiled table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteTableEntry {
    /// URL pattern, as declared. A trailing `*` matches everything underneath;
    /// anything else is an exact path ([`matches_route_pattern`]).
    pub path: String,
    #[serde(flatten)]
    pub mode: ResolvedRouteMode,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub auth: RouteAuth,
}

/// A domain's routes, compiled and resolved, in manifest order.
///
/// Constructed only by [`DomainConfig::route_table`], which refuses an
/// unresolved origin — so there is no way to hold a half-filled table, and
/// every renderer downstream can serialize without re-checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteTable {
    /// The manifest's `name` (its file stem), for error messages.
    pub domain: String,
    pub entries: Vec<RouteTableEntry>,
}

impl DomainConfig {
    /// Compile this domain's declared routes into one resolved table.
    ///
    /// Manifest order is preserved because it is the matching order — see the
    /// module doc. Fails, naming the route, when `placement` cannot resolve an
    /// origin: the alternative is an entry silently missing from the table,
    /// which serves that path from whichever shorter entry matches instead of
    /// failing.
    pub fn route_table(&self, placement: &dyn RoutePlacement) -> Result<RouteTable> {
        let mut entries = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            entries.push(RouteTableEntry {
                path: route.path.clone(),
                mode: self.resolve_mode(route, placement)?,
                headers: route.headers.clone(),
                auth: route_auth(&route.path, placement.auth_required_prefixes()),
            });
        }
        Ok(RouteTable {
            domain: self.name.clone(),
            entries,
        })
    }

    fn resolve_mode(
        &self,
        route: &DomainRoute,
        placement: &dyn RoutePlacement,
    ) -> Result<ResolvedRouteMode> {
        Ok(match &route.mode {
            RouteMode::Static { component } => ResolvedRouteMode::Static {
                component: component.clone(),
                origin: self.require_origin(
                    route,
                    "static",
                    component,
                    placement.asset_origin(component, &route.path),
                )?,
            },
            RouteMode::StaticBucket { bucket } => ResolvedRouteMode::StaticBucket {
                bucket: bucket.clone(),
                binding: r2_binding_name(bucket),
            },
            RouteMode::Backend {
                component,
                origin_path,
                ..
            } => ResolvedRouteMode::Backend {
                component: component.clone(),
                origin: self.require_origin(
                    route,
                    "backend",
                    component,
                    placement.backend_origin(component, &route.path),
                )?,
                rewrite: route_rewrite(&route.path, origin_path.as_ref()),
            },
            RouteMode::Redirect { target, status } => ResolvedRouteMode::Redirect {
                target: target.clone(),
                status: *status,
            },
        })
    }

    fn require_origin(
        &self,
        route: &DomainRoute,
        mode: &str,
        component: &str,
        resolved: Option<String>,
    ) -> Result<String> {
        resolved.map(Ok).unwrap_or_else(|| {
            bail!(
                "domain {}: route {:?} ({mode}, component {component:?}) has no resolved origin \
                 yet. Refusing to compile a partial route table — a missing entry does not 503, \
                 it falls through to whichever shorter route matches (the catch-all, usually) \
                 and serves the wrong thing with a 200.",
                self.name,
                route.path,
            )
        })
    }

    /// The `ROUTE_HEADERS` / `MESOFACT_ROUTE_HEADERS` wire value (R746) — the
    /// header column of [`Self::route_table`], which is the only column those
    /// two bindings carry until R898-F2/F3 widen them.
    ///
    /// Needs no [`RoutePlacement`], which is why it is here and not on
    /// [`RouteTable`] alone: the reconcilers that set those bindings run before
    /// anything is placed. Both spellings share [`headers_json`], so the
    /// projection cannot drift from the table it projects.
    pub fn route_headers_json(&self) -> String {
        headers_json(self.routes.iter().map(|r| (r.path.as_str(), &r.headers)))
    }

    /// The declared route that governs `path` — the same walk
    /// [`RouteTable::match_path`] makes, over the routes instead of over the
    /// compiled entries.
    ///
    /// Placement-free, and here for exactly the reason
    /// [`Self::route_headers_json`] is: a consumer that runs BEFORE anything is
    /// placed cannot compile a table to ask. [`crate::inner_door::plan`] is that
    /// consumer, and for it the dependency is not merely inconvenient but
    /// **circular** — [`CdnPlacement::backend_origin`] resolves a route's origin
    /// out of [`InnerDoorPlan::resolve_addresses`]' output, which is derived from
    /// the very plan that would be asking (R898-F1's handoff states that keying).
    ///
    /// One rule, two walks, pinned by
    /// `the_declared_walk_and_the_compiled_walk_pick_the_same_route` — the same
    /// arrangement [`headers_json`] already has, and for the same reason.
    ///
    /// [`InnerDoorPlan::resolve_addresses`]: crate::inner_door::InnerDoorPlan::resolve_addresses
    pub fn route_for_path(&self, path: &str) -> Option<&DomainRoute> {
        first_match(self.routes.iter().map(|r| (r.path.as_str(), r)), path)
    }
}

impl RouteTable {
    /// The entry a request for `path` is served by — FIRST match, no merging.
    pub fn match_path(&self, path: &str) -> Option<&RouteTableEntry> {
        first_match(self.entries.iter().map(|e| (e.path.as_str(), e)), path)
    }

    /// The full table as the JSON both doors will consume (R898-F2/F3).
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.entries).unwrap_or_else(|_| "[]".to_string())
    }

    /// This table's header column, byte-identical to
    /// [`DomainConfig::route_headers_json`] — the same routes, the same order,
    /// the same dropped-when-headerless rule.
    pub fn headers_json(&self) -> String {
        headers_json(self.entries.iter().map(|e| (e.path.as_str(), &e.headers)))
    }
}

/// The route-driven domain routing `service`, compiled against `placement`.
///
/// The widened twin of [`route_headers_for_service`](crate::config::route_headers_for_service):
/// same lookup, same `.yah/domains/` read, the whole table instead of its
/// header column. `None` when no route-driven domain routes the service.
pub fn route_table_for_service(
    workspace_root: &std::path::Path,
    service: &str,
    placement: &dyn RoutePlacement,
) -> Result<Option<RouteTable>> {
    let domains = load_domains(&crate::paths::domains_dir(workspace_root))?;
    domain_serving_service(&domains, service)
        .map(|d| d.route_table(placement))
        .transpose()
}

/// The one serializer of the header wire format — `[{path, headers}]` in
/// manifest order, headerless routes dropped.
///
/// A free function over `(path, headers)` pairs rather than a method, because
/// it has two callers on purpose: the declared routes (pre-placement) and the
/// compiled table. Two walks, one format, and a test pinning that they agree.
pub(crate) fn headers_json<'a>(
    rules: impl Iterator<Item = (&'a str, &'a BTreeMap<String, String>)>,
) -> String {
    #[derive(Serialize)]
    struct Rule<'a> {
        path: &'a str,
        headers: &'a BTreeMap<String, String>,
    }
    let rules: Vec<Rule<'_>> = rules
        .filter(|(_, headers)| !headers.is_empty())
        .map(|(path, headers)| Rule { path, headers })
        .collect();
    serde_json::to_string(&rules).unwrap_or_else(|_| "[]".to_string())
}

/// The one implementation of *which* rule governs a path: manifest order,
/// first match wins, no merging across rules.
///
/// Generic over the payload for the same reason [`headers_json`] is generic over
/// the pair source — it has two callers on purpose, the declared routes
/// (pre-placement) and the compiled table, and they must not be able to pick
/// different rules. R746 pinned the semantics in TS with the reasoning at
/// `router.ts:400-411`; R749-F3 carried them into Rust.
pub(crate) fn first_match<'a, T>(
    rules: impl Iterator<Item = (&'a str, T)>,
    path: &str,
) -> Option<T> {
    rules
        .into_iter()
        .find(|(pattern, _)| matches_route_pattern(pattern, path))
        .map(|(_, payload)| payload)
}

/// `true` when `path` is served by `pattern`.
///
/// A trailing `*` matches the bare prefix and every `/`-delimited descendant;
/// anything else is an exact match. Never a raw `starts_with` — `/application`
/// must not reach a `/app/*` route.
///
/// Mirrors `mesofact::route_headers::matches_route_pattern` and the Worker's
/// `matchesRoutePattern` byte for byte, including the deliberate inclusion of
/// the BARE prefix: `/app` is the URL a link points at, it resolves to
/// `app/index.html` through the clean-URL rule, and an entry that skipped it
/// would miss the very document it exists for.
pub fn matches_route_pattern(pattern: &str, path: &str) -> bool {
    let Some(head) = pattern.strip_suffix('*') else {
        return path == pattern;
    };
    let prefix = head.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

/// Whether a door protecting `required` prefixes protects every request
/// `route_path` matches.
///
/// Conservative on purpose: a route is [`RouteAuth::Bearer`] only when a
/// required prefix covers the WHOLE pattern. A `/*` catch-all against a door
/// requiring `/admin` is anonymous here — most of what it serves is — and the
/// `/admin` requirement is carried by whichever entry actually claims that
/// prefix. Reporting the catch-all as protected would tell the topology view
/// that a surface is authenticated when nearly all of it is not.
fn route_auth(route_path: &str, required: &[String]) -> RouteAuth {
    let route_prefix = route_path.strip_suffix('*').unwrap_or(route_path);
    let route_prefix = route_prefix.trim_end_matches('/');
    let covered = required.iter().any(|req| {
        let req = req.trim_end_matches('/');
        // `"/"` trims to `""` — the whole-surface requirement, which is the
        // only value `PasswayAuth` has for "everything" (it is an allowlist
        // with no exclusion form).
        req.is_empty() || route_prefix == req || route_prefix.starts_with(&format!("{req}/"))
    });
    if covered {
        RouteAuth::Bearer
    } else {
        RouteAuth::Anonymous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FrontDoor;

    /// A placement that resolves everything, so a test asserting on the table's
    /// SHAPE is not also asserting on a resolver.
    struct FixedPlacement {
        auth: Vec<String>,
    }

    impl Default for FixedPlacement {
        fn default() -> Self {
            Self { auth: vec![] }
        }
    }

    impl RoutePlacement for FixedPlacement {
        fn asset_origin(&self, component: &str, _path: &str) -> Option<String> {
            Some(format!("https://cdn.example/{component}"))
        }
        fn backend_origin(&self, component: &str, _path: &str) -> Option<String> {
            Some(format!("http://unit.example/{component}"))
        }
        fn auth_required_prefixes(&self) -> &[String] {
            &self.auth
        }
    }

    /// Resolves nothing — the shape a caller has before placement runs.
    struct NoPlacement;
    impl RoutePlacement for NoPlacement {
        fn asset_origin(&self, _component: &str, _path: &str) -> Option<String> {
            None
        }
        fn backend_origin(&self, _component: &str, _path: &str) -> Option<String> {
            None
        }
    }

    fn domain(name: &str, routes: Vec<DomainRoute>) -> DomainConfig {
        DomainConfig {
            schema_version: 1,
            name: name.to_string(),
            domain: format!("{name}.example"),
            front_door: FrontDoor::Worker,
            cdn_bucket: "example".into(),
            worker_bundle_path: None,
            routes,
        }
    }

    fn route(path: &str, mode: RouteMode, headers: &[(&str, &str)]) -> DomainRoute {
        DomainRoute {
            path: path.to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            mode,
        }
    }

    /// R898-F3 — a backend route whose origin serves it at a different prefix
    /// compiles that swap into the table, and the swap survives `to_json`.
    ///
    /// This is the datum the Worker's two hardcoded `if` blocks carried before
    /// they were deleted: without it an entry proxies `/api/issues` to
    /// `<origin>/api/issues` and quietly changes the upstream contract. The
    /// identity case stays absent from the wire — a `{from: "/api", to: "/api"}`
    /// is a branch at the door that can never do anything.
    #[test]
    fn a_backend_routes_prefix_rewrite_compiles_and_round_trips() {
        let cfg = domain(
            "acme",
            vec![
                route(
                    "/api/issues*",
                    RouteMode::Backend {
                        component: "acme/issues".into(),
                        origin: "https://declared.invalid".into(),
                        origin_path: Some("/issues".into()),
                    },
                    &[],
                ),
                route(
                    "/api/plain*",
                    RouteMode::Backend {
                        component: "acme/plain".into(),
                        origin: "https://declared.invalid".into(),
                        origin_path: None,
                    },
                    &[],
                ),
                route(
                    "/api/same*",
                    RouteMode::Backend {
                        component: "acme/same".into(),
                        origin: "https://declared.invalid".into(),
                        origin_path: Some("/api/same".into()),
                    },
                    &[],
                ),
            ],
        );
        let table = cfg.route_table(&FixedPlacement::default()).unwrap();

        assert_eq!(
            table.entries[0].mode,
            ResolvedRouteMode::Backend {
                component: "acme/issues".into(),
                origin: "http://unit.example/acme/issues".into(),
                rewrite: Some(RouteRewrite {
                    from: "/api/issues".into(),
                    to: "/issues".into(),
                }),
            },
            "the declared origin_path becomes the entry's {{from, to}} prefix swap",
        );
        assert!(
            matches!(
                table.entries[1].mode,
                ResolvedRouteMode::Backend { rewrite: None, .. }
            ),
            "an undeclared origin_path is an identity proxy, not a rewrite",
        );
        assert!(
            matches!(
                table.entries[2].mode,
                ResolvedRouteMode::Backend { rewrite: None, .. }
            ),
            "a declared origin_path equal to the route's own prefix is the identity too",
        );

        let json = table.to_json();
        let wire: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            wire[0]["rewrite"],
            serde_json::json!({"from": "/api/issues", "to": "/issues"}),
            "the Worker reads both halves off the wire — it must not re-derive \
             the public prefix from the pattern",
        );
        assert!(
            wire[1].get("rewrite").is_none() && wire[2].get("rewrite").is_none(),
            "identity entries carry no rewrite key at all: {json}",
        );
    }

    /// yah.dev as it is declared today: one static catch-all carrying the
    /// R749-F3 probe header. The degenerate case the widening must not move.
    fn yah_dev() -> DomainConfig {
        domain(
            "yah-dev",
            vec![route(
                "/*",
                RouteMode::Static {
                    component: "yah-marketing/site".into(),
                },
                &[("X-Route-Header-Probe", "r749-f3")],
            )],
        )
    }

    // ── R560-F13: bucket-root static routes ─────────────────────────────────

    #[test]
    fn r2_binding_name_is_the_bucket_upcased_with_hyphens_mapped() {
        assert_eq!(r2_binding_name("noisetable-releases"), "R2_NOISETABLE_RELEASES");
        assert_eq!(r2_binding_name("nt-assets-2"), "R2_NT_ASSETS_2");
    }

    /// A bucket route needs no placement — it compiles under [`NoPlacement`] —
    /// and its wire entry is `mode = "static"` plus bucket and binding, with no
    /// origin: the door tells it from a component entry by `binding` alone.
    #[test]
    fn a_bucket_route_compiles_to_its_binding_with_no_placement() {
        let dom = domain(
            "cdn",
            vec![
                route(
                    "/engine/*",
                    RouteMode::StaticBucket {
                        bucket: "noisetable-releases".into(),
                    },
                    &[],
                ),
                route(
                    "/nt-cas/*",
                    RouteMode::StaticBucket {
                        bucket: "noisetable-assets".into(),
                    },
                    &[("Cache-Control", "immutable")],
                ),
                route(
                    "/dev/*",
                    RouteMode::StaticBucket {
                        bucket: "noisetable-releases".into(),
                    },
                    &[],
                ),
            ],
        );
        let table = dom.route_table(&NoPlacement).unwrap();
        assert_eq!(
            table.entries[0].mode,
            ResolvedRouteMode::StaticBucket {
                bucket: "noisetable-releases".into(),
                binding: "R2_NOISETABLE_RELEASES".into(),
            }
        );
        let wire: serde_json::Value = serde_json::from_str(&table.to_json()).unwrap();
        assert_eq!(
            wire[0],
            serde_json::json!({
                "path": "/engine/*",
                "mode": "static",
                "bucket": "noisetable-releases",
                "binding": "R2_NOISETABLE_RELEASES",
                "auth": "anonymous",
            })
        );
        assert_eq!(wire[1]["headers"]["Cache-Control"], "immutable");
        assert_eq!(
            r2_bucket_bindings(&table.entries),
            vec![
                (
                    "R2_NOISETABLE_RELEASES".to_string(),
                    "noisetable-releases".to_string()
                ),
                (
                    "R2_NOISETABLE_ASSETS".to_string(),
                    "noisetable-assets".to_string()
                ),
            ],
            "one binding per DISTINCT bucket, first-use order"
        );
    }

    /// A component entry keeps its exact wire shape, and a component-only
    /// table binds no bucket.
    #[test]
    fn a_component_entry_keeps_its_origin_shape_and_binds_no_bucket() {
        let table = yah_dev().route_table(&FixedPlacement::default()).unwrap();
        assert_eq!(
            table.to_json(),
            r#"[{"path":"/*","mode":"static","component":"yah-marketing/site","origin":"https://cdn.example/yah-marketing/site","headers":{"X-Route-Header-Probe":"r749-f3"},"auth":"anonymous"}]"#
        );
        assert!(r2_bucket_bindings(&table.entries).is_empty());
    }

    // ── R898-F1 acceptance ──────────────────────────────────────────────────

    /// The ticket's own criterion: an ordered mix of static, backend and
    /// redirect routes compiles to ONE table whose entries carry path, mode,
    /// resolved origin, headers and auth, in manifest order.
    #[test]
    fn a_mixed_domain_compiles_to_one_ordered_table_with_resolved_origins() {
        let dom = domain(
            "mixed",
            vec![
                route(
                    "/app/*",
                    RouteMode::Static {
                        component: "acme/app".into(),
                    },
                    &[("Cross-Origin-Opener-Policy", "same-origin")],
                ),
                route(
                    "/api/*",
                    RouteMode::Backend {
                        component: "acme/api".into(),
                        // The DECLARED origin, which must not reach the table:
                        // it is the Worker arm's fetch() target and nothing
                        // reads it under passway.
                        origin: "https://declared.invalid".into(),
                        origin_path: None,
                    },
                    &[],
                ),
                route(
                    "/old",
                    RouteMode::Redirect {
                        target: "https://acme.example/new".into(),
                        status: 301,
                    },
                    &[],
                ),
                route(
                    "/*",
                    RouteMode::Static {
                        component: "acme/site".into(),
                    },
                    &[],
                ),
            ],
        );

        let table = dom.route_table(&FixedPlacement::default()).unwrap();

        assert_eq!(
            table
                .entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["/app/*", "/api/*", "/old", "/*"],
            "manifest order is the matching order and must survive compilation",
        );

        assert_eq!(
            table.entries[0].mode,
            ResolvedRouteMode::Static {
                component: "acme/app".into(),
                origin: "https://cdn.example/acme/app".into(),
            }
        );
        assert_eq!(
            table.entries[0]
                .headers
                .get("Cross-Origin-Opener-Policy")
                .map(String::as_str),
            Some("same-origin")
        );
        assert_eq!(table.entries[0].auth, RouteAuth::Anonymous);

        assert_eq!(
            table.entries[1].mode,
            ResolvedRouteMode::Backend {
                component: "acme/api".into(),
                origin: "http://unit.example/acme/api".into(),
                rewrite: None,
            },
            "the RESOLVED unit address, never the manifest's declared `origin`",
        );

        assert_eq!(
            table.entries[2].mode,
            ResolvedRouteMode::Redirect {
                target: "https://acme.example/new".into(),
                status: 301,
            },
            "a redirect carries its own target and needs no origin",
        );
    }

    /// The wire shape F2/F3 parse: mode is the discriminator, the resolved
    /// origin rides beside it, a redirect has no `origin` key at all, and a
    /// headerless entry carries no `headers` key.
    #[test]
    fn the_table_json_carries_mode_origin_headers_and_auth_per_entry() {
        let dom = domain(
            "mixed",
            vec![
                route(
                    "/api/*",
                    RouteMode::Backend {
                        component: "acme/api".into(),
                        origin: "https://declared.invalid".into(),
                        origin_path: None,
                    },
                    &[],
                ),
                route(
                    "/old",
                    RouteMode::Redirect {
                        target: "https://acme.example/new".into(),
                        status: 308,
                    },
                    &[],
                ),
            ],
        );
        let json = dom
            .route_table(&FixedPlacement::default())
            .unwrap()
            .to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let entries = parsed.as_array().unwrap();

        assert_eq!(entries[0]["mode"], "backend");
        assert_eq!(entries[0]["origin"], "http://unit.example/acme/api");
        assert_eq!(entries[0]["auth"], "anonymous");
        assert!(
            entries[0].get("headers").is_none(),
            "a headerless entry carries no headers key: {json}"
        );

        assert_eq!(entries[1]["mode"], "redirect");
        assert_eq!(entries[1]["target"], "https://acme.example/new");
        assert_eq!(entries[1]["status"], 308);
        assert!(
            entries[1].get("origin").is_none(),
            "a redirect has no origin: {json}"
        );
    }

    /// **The degenerate case must not move.** yah.dev's single catch-all plus
    /// its probe header compiles to a table whose header half is byte-identical
    /// to what `route_headers_json` emits today — so nothing deployed changes
    /// behaviour when F2/F3 land.
    #[test]
    fn yah_devs_header_half_is_byte_identical_to_route_headers_json() {
        let dom = yah_dev();
        let declared = dom.route_headers_json();
        assert_eq!(
            declared, r#"[{"path":"/*","headers":{"X-Route-Header-Probe":"r749-f3"}}]"#,
            "the live ROUTE_HEADERS / MESOFACT_ROUTE_HEADERS value for yah.dev",
        );
        assert_eq!(
            dom.route_table(&FixedPlacement::default())
                .unwrap()
                .headers_json(),
            declared,
            "the compiled table's header column IS the shipped binding value",
        );
    }

    /// The same equality on a table that exercises both of the projection's
    /// rules — order preserved, headerless entries dropped.
    #[test]
    fn the_header_projection_agrees_with_the_declaration_on_a_mixed_table() {
        let dom = domain(
            "mixed",
            vec![
                route(
                    "/app/*",
                    RouteMode::Static {
                        component: "acme/app".into(),
                    },
                    &[("Cross-Origin-Embedder-Policy", "require-corp")],
                ),
                route(
                    "/*",
                    RouteMode::Static {
                        component: "acme/site".into(),
                    },
                    &[],
                ),
            ],
        );
        let table = dom.route_table(&FixedPlacement::default()).unwrap();
        assert_eq!(table.headers_json(), dom.route_headers_json());
        assert_eq!(
            table.headers_json(),
            r#"[{"path":"/app/*","headers":{"Cross-Origin-Embedder-Policy":"require-corp"}}]"#,
            "the headerless catch-all contributes no rule",
        );
    }

    // ── refusal, matching, auth ─────────────────────────────────────────────

    /// An unresolved origin fails the compile naming the route. The refusal is
    /// the point: the alternative is a dropped entry, which falls through to
    /// the catch-all and serves the wrong thing with a 200.
    #[test]
    fn an_unresolved_origin_refuses_the_table_rather_than_dropping_the_entry() {
        let err = yah_dev().route_table(&NoPlacement).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("yah-dev"), "{msg}");
        assert!(msg.contains("/*"), "{msg}");
        assert!(msg.contains("yah-marketing/site"), "{msg}");
    }

    /// A redirect resolves with no placement at all — it carries its own
    /// target, so a domain of pure redirects compiles before anything deploys.
    #[test]
    fn a_redirect_needs_no_placement() {
        let dom = domain(
            "redirects",
            vec![route(
                "/old/*",
                RouteMode::Redirect {
                    target: "https://acme.example/new".into(),
                    status: 308,
                },
                &[],
            )],
        );
        assert!(dom.route_table(&NoPlacement).is_ok());
    }

    /// FIRST match wins, and matching is segment-aware — `/application` is not
    /// under `/app`. Both halves of the rule this table inherits from R746.
    #[test]
    fn first_match_wins_and_app_does_not_capture_application() {
        let dom = domain(
            "mixed",
            vec![
                route(
                    "/app/*",
                    RouteMode::Static {
                        component: "acme/app".into(),
                    },
                    &[],
                ),
                route(
                    "/*",
                    RouteMode::Static {
                        component: "acme/site".into(),
                    },
                    &[],
                ),
            ],
        );
        let table = dom.route_table(&FixedPlacement::default()).unwrap();

        assert_eq!(table.match_path("/app").unwrap().path, "/app/*");
        assert_eq!(table.match_path("/app/x").unwrap().path, "/app/*");
        assert_eq!(
            table.match_path("/application").unwrap().path,
            "/*",
            "a bare starts_with would have routed this to the app bundle",
        );
        assert_eq!(table.match_path("/").unwrap().path, "/*");
    }

    /// R898-F2: the pre-placement walk and the compiled walk are one rule.
    /// `DomainConfig::route_for_path` exists because the inner-door planner runs
    /// before any placement and cannot compile a table to ask (the origin
    /// resolution would be circular) — so the thing that must be pinned is that
    /// it never picks a different route than the table would.
    #[test]
    fn the_declared_walk_and_the_compiled_walk_pick_the_same_route() {
        let dom = domain(
            "mixed",
            vec![
                route(
                    "/app/*",
                    RouteMode::Static {
                        component: "acme/app".into(),
                    },
                    &[("x-a", "1")],
                ),
                route(
                    "/api/thing",
                    RouteMode::Backend {
                        component: "acme/api".into(),
                        origin: "https://declared.invalid".into(),
                        origin_path: None,
                    },
                    &[],
                ),
                route(
                    "/*",
                    RouteMode::Static {
                        component: "acme/site".into(),
                    },
                    &[("x-b", "2")],
                ),
            ],
        );
        let table = dom.route_table(&FixedPlacement::default()).unwrap();

        for path in [
            "/",
            "/app",
            "/app/x",
            "/application",
            "/api/thing",
            "/api/thing/more",
            "/anything",
        ] {
            let declared = dom.route_for_path(path);
            let compiled = table.match_path(path);
            assert_eq!(
                declared.map(|r| r.path.as_str()),
                compiled.map(|e| e.path.as_str()),
                "{path}"
            );
            assert_eq!(
                declared.map(|r| &r.headers),
                compiled.map(|e| &e.headers),
                "{path}"
            );
        }
    }

    #[test]
    fn matches_route_pattern_mirrors_the_worker_and_mesofact_matchers() {
        assert!(matches_route_pattern("/*", "/anything/at/all"));
        assert!(matches_route_pattern("/app/*", "/app"));
        assert!(matches_route_pattern("/app/*", "/app/"));
        assert!(!matches_route_pattern("/app/*", "/application"));
        assert!(matches_route_pattern("/exact", "/exact"));
        assert!(!matches_route_pattern("/exact", "/exact/more"));
    }

    /// Auth is the door's `require_prefixes`, read per route: the protected
    /// prefix's own entry is `bearer`, and a catch-all that mostly serves
    /// anonymous traffic is not reported as protected.
    #[test]
    fn auth_follows_the_doors_required_prefixes() {
        let dom = domain(
            "mixed",
            vec![
                route(
                    "/admin/*",
                    RouteMode::Static {
                        component: "acme/admin".into(),
                    },
                    &[],
                ),
                route(
                    "/*",
                    RouteMode::Static {
                        component: "acme/site".into(),
                    },
                    &[],
                ),
            ],
        );
        let placement = FixedPlacement {
            auth: vec!["/admin".to_string()],
        };
        let table = dom.route_table(&placement).unwrap();
        assert_eq!(table.entries[0].auth, RouteAuth::Bearer);
        assert_eq!(table.entries[1].auth, RouteAuth::Anonymous);

        // `"/"` is `PasswayAuth`'s only whole-surface value — it covers both.
        let whole = FixedPlacement {
            auth: vec!["/".to_string()],
        };
        let table = dom.route_table(&whole).unwrap();
        assert!(table.entries.iter().all(|e| e.auth == RouteAuth::Bearer));
    }

    /// `CdnPlacement` resolves through the identity derivation that already
    /// owns the mapping, rather than a second copy of it.
    #[test]
    fn cdn_placement_resolves_static_by_prefix_and_backend_by_mesh_ident() {
        let placement = CdnPlacement {
            cdn_base: "https://cdn.yah.dev/".into(),
            env: "prod".into(),
            addresses: [(
                component_workload_ident("yah-marketing", "api"),
                "100.64.0.3:8080".to_string(),
            )]
            .into_iter()
            .collect(),
            auth_required_prefixes: vec![],
        };
        assert_eq!(
            placement.asset_origin("yah-marketing/site", "/*").unwrap(),
            "https://cdn.yah.dev/yah-marketing/prod",
            "the same string plan_domain_worker computes today",
        );
        assert_eq!(
            placement
                .backend_origin("yah-marketing/api", "/api/*")
                .unwrap(),
            "http://100.64.0.3:8080",
        );
        assert_eq!(
            placement.backend_origin("yah-marketing/absent", "/x"),
            None,
            "an undeployed unit resolves to nothing, which refuses the compile",
        );
        assert_eq!(placement.asset_origin("malformed", "/*"), None);
    }
}
