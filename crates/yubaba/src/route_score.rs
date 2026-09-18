//! Nearest-first scoring for service-to-service mesh calls (R330-F17).
//!
//! Pure, transport-free: given a caller's [`NodeLocality`] and a candidate's,
//! answers "how bad is this route" as `score = alpha * latency_class + beta *
//! egress_cost`. Nothing here talks to the network or to raft — the caller
//! supplies both localities and a [`RouteTables`]/[`RouteWeights`] pair, and
//! gets back a ranking. [`crate::mesh_directory`] is what actually finds the
//! candidates; this module only orders them.
//!
//! # Why two axes, not one
//!
//! A single RTT-based score would silently prefer a cross-cloud same-region
//! route over a same-provider cross-region one, and the cross-cloud route
//! bleeds egress money on every call. `latency_class` (a static geo-distance
//! table, keyed by region pair) and `egress_cost` (a static transit-cost
//! table, keyed by provider pair) are combined with independent weights so an
//! operator can tune how much either one matters without the other moving.
//!
//! # The default weights are load-bearing, not decorative
//!
//! `RouteWeights::DEFAULT` (alpha=1.0, beta=1.5) is chosen so that, with the
//! default tables, a same-provider route one region hop away outscores a
//! same-region route on a different provider — i.e. egress cost dominates a
//! single region hop for a chatty path. Concretely, with the default tables:
//! us-east/hetzner vs us-west/aws, called from a us-west/hetzner caller:
//! `score(us-east, hetzner) = 1.0*2 + 1.5*0 = 2.0`,
//! `score(us-west, aws) = 1.0*0 + 1.5*2 = 3.0` — the cross-region,
//! same-provider candidate wins. That relationship (`alpha < beta`) is what
//! `route_score::tests` pins down; changing the defaults without re-checking
//! those tests silently flips which axis dominates.
//!
//! # Egress asymmetry lives in the table, not in code
//!
//! [`RouteTables::transit_cost`] is a **directional** lookup —
//! `(from_provider, to_provider)` — deliberately not normalized to an
//! unordered pair. That is what lets `.yah/infra/transit-cost.toml` encode
//! "calling a peer hosted on `cloudflare-r2` costs nothing" without also
//! claiming the reverse (a call *originating* from R2 costs nothing too,
//! which is not a claim this table needs to make since R2 runs no compute).
//! Same-provider (`from == to`) is the one case handled in code rather than
//! the table, because it is a tautology ("calling yourself costs nothing"),
//! not a heuristic an operator would ever want to override.
//!
//! @yah:ticket(R330-F17, "Nearest-first service-to-service routing: mesh discovery surfaces region, callers prefer same-region target")
//! @yah:status(active)
//! @yah:at(2026-09-13T19:56:57Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R523)
//! @arch:see(.yah/docs/working/W059-almanac-release-feed.md)

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

/// A node's (region, provider) tuple — the two axes [`score`] scores on.
///
/// Both `Option` because a voter can legitimately have no region declared
/// (a `rig`, one failure domain) and a node predating R859-F2 has no provider
/// row at all. Missing information degrades to
/// [`RouteTables::default_geo_distance`] / [`RouteTables::default_transit_cost`]
/// — "unknown" is scored as "far", never as "free" or "local".
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct NodeLocality {
    pub region: Option<String>,
    pub provider: Option<String>,
}

impl NodeLocality {
    pub fn new(region: Option<String>, provider: Option<String>) -> Self {
        Self { region, provider }
    }
}

/// Tunable weights on [`score`]'s two terms. See the module doc for why the
/// defaults are the specific numbers they are.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RouteWeights {
    /// Multiplier on `latency_class` (region distance).
    pub alpha: f64,
    /// Multiplier on `egress_cost` (transit cost).
    pub beta: f64,
}

impl RouteWeights {
    pub const DEFAULT: RouteWeights = RouteWeights {
        alpha: 1.0,
        beta: 1.5,
    };
}

impl Default for RouteWeights {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The two static heuristic tables `score` reads, plus their fallback values
/// for a pair neither table names.
///
/// Loaded from [`RouteTables::defaults`] and optionally overridden by
/// `.yah/infra/transit-cost.toml` (see [`RouteTables::load`]) — the same file
/// F16-style placement scoring is meant to share, so an operator's negotiated
/// egress discount is declared once and read by both the scheduler and this
/// router.
#[derive(Debug, Clone)]
pub struct RouteTables {
    /// Keyed by an UNORDERED region pair (looked up both ways) — geographic
    /// distance is symmetric.
    geo_distance: HashMap<(String, String), u32>,
    /// Keyed by a DIRECTIONAL provider pair `(from, to)` — see the module doc
    /// on why this is not normalized.
    transit_cost: HashMap<(String, String), u32>,
    default_geo_distance: u32,
    default_transit_cost: u32,
}

impl RouteTables {
    /// The built-in table, matching the examples in R330-F17's ticket text.
    /// Same-region and same-provider are handled in [`Self::geo_distance`] /
    /// [`Self::transit_cost`] directly and are not rows here.
    pub fn defaults() -> Self {
        let mut geo_distance = HashMap::new();
        for (a, b, d) in [
            ("us-west", "us-central", 1),
            ("us-west", "us-east", 2),
            ("us-west", "eu-west", 4),
            ("us-central", "us-east", 1),
            ("us-central", "eu-west", 3),
            ("us-east", "eu-west", 2),
        ] {
            geo_distance.insert((a.to_string(), b.to_string()), d);
        }

        let mut transit_cost = HashMap::new();
        for (from, to, c) in [
            ("hetzner", "aws", 2u32),
            ("aws", "hetzner", 2),
            ("hetzner", "ovh", 2),
            ("ovh", "hetzner", 2),
            ("hetzner", "vultr", 2),
            ("vultr", "hetzner", 2),
            ("aws", "vultr", 2),
            ("vultr", "aws", 2),
            ("aws", "ovh", 2),
            ("ovh", "aws", 2),
            // R2 egress-to-internet is free (Cloudflare's model): a call
            // TO a peer hosted on cloudflare-r2 costs nothing, from any
            // provider. The reverse is intentionally NOT declared — R2
            // runs no compute, so "a call originating from R2" is not a
            // real route, and leaving it undeclared falls back to
            // `default_transit_cost` rather than asserting a claim about a
            // case that cannot occur.
            ("hetzner", "cloudflare-r2", 0),
            ("aws", "cloudflare-r2", 0),
            ("ovh", "cloudflare-r2", 0),
            ("vultr", "cloudflare-r2", 0),
            ("static", "cloudflare-r2", 0),
        ] {
            transit_cost.insert((from.to_string(), to.to_string()), c);
        }

        Self {
            geo_distance,
            transit_cost,
            default_geo_distance: 4,
            default_transit_cost: 2,
        }
    }

    /// [`Self::defaults`], with any rows in `path` layered on top — an
    /// existing row is replaced, a new one is added. Missing file is not an
    /// error (defaults apply); a malformed file is reported so an operator
    /// notices a typo'd override rather than silently falling back to
    /// defaults it thinks it changed.
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut tables = Self::defaults();
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(tables),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        let file: TransitCostFile =
            toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        for row in file.geo_distance {
            tables
                .geo_distance
                .insert((row.a, row.b), row.distance);
        }
        for row in file.transit_cost {
            tables.transit_cost.insert((row.from, row.to), row.cost);
        }
        if let Some(d) = file.default_geo_distance {
            tables.default_geo_distance = d;
        }
        if let Some(d) = file.default_transit_cost {
            tables.default_transit_cost = d;
        }
        Ok(tables)
    }

    /// Weights declared alongside the tables in the same file, if any —
    /// loaded separately from [`Self::load`] since a caller with no override
    /// file still wants [`RouteWeights::DEFAULT`].
    pub fn load_weights(path: &Path) -> Result<RouteWeights, String> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RouteWeights::DEFAULT),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };
        let file: TransitCostFile =
            toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        Ok(file
            .weights
            .map(|w| RouteWeights {
                alpha: w.alpha,
                beta: w.beta,
            })
            .unwrap_or(RouteWeights::DEFAULT))
    }

    /// Latency class between two regions. `0` for the same region (including
    /// both `None`, since "no region declared" on both sides is not evidence
    /// of distance); an undeclared pair falls back to
    /// [`Self::default_geo_distance`] — unknown scores as far, not as close.
    pub fn geo_distance(&self, a: &str, b: &str) -> u32 {
        if a == b {
            return 0;
        }
        self.geo_distance
            .get(&(a.to_string(), b.to_string()))
            .or_else(|| self.geo_distance.get(&(b.to_string(), a.to_string())))
            .copied()
            .unwrap_or(self.default_geo_distance)
    }

    /// Directional egress cost of a call FROM a peer on `from`'s provider TO
    /// one on `to`'s. `0` for the same provider (see module doc); an
    /// undeclared direction falls back to [`Self::default_transit_cost`].
    pub fn transit_cost(&self, from: &str, to: &str) -> u32 {
        if from == to {
            return 0;
        }
        self.transit_cost
            .get(&(from.to_string(), to.to_string()))
            .copied()
            .unwrap_or(self.default_transit_cost)
    }
}

#[derive(Debug, Deserialize, Default)]
struct TransitCostFile {
    #[serde(default)]
    weights: Option<WeightsToml>,
    #[serde(default)]
    geo_distance: Vec<GeoRow>,
    #[serde(default)]
    transit_cost: Vec<CostRow>,
    #[serde(default)]
    default_geo_distance: Option<u32>,
    #[serde(default)]
    default_transit_cost: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct WeightsToml {
    alpha: f64,
    beta: f64,
}

#[derive(Debug, Deserialize)]
struct GeoRow {
    a: String,
    b: String,
    distance: u32,
}

#[derive(Debug, Deserialize)]
struct CostRow {
    from: String,
    to: String,
    cost: u32,
}

/// One candidate's score, with the raw inputs kept alongside the result —
/// this is the shape `--verbose` logs so an operator can see "why X over Y"
/// instead of just the final ordering (R330-F17 gotcha: the formula MUST log
/// its inputs).
#[derive(Debug, Clone)]
pub struct ScoredCandidate<T> {
    pub key: T,
    pub locality: NodeLocality,
    pub latency_class: u32,
    pub egress_cost: u32,
    pub score: f64,
}

/// `alpha * latency_class + beta * egress_cost` for one (caller, candidate)
/// pair, plus the two raw inputs that produced it.
pub fn score(
    caller: &NodeLocality,
    candidate: &NodeLocality,
    tables: &RouteTables,
    weights: &RouteWeights,
) -> (u32, u32, f64) {
    let latency_class = match (&caller.region, &candidate.region) {
        (Some(a), Some(b)) => tables.geo_distance(a, b),
        _ => tables.default_geo_distance,
    };
    let egress_cost = match (&caller.provider, &candidate.provider) {
        (Some(a), Some(b)) => tables.transit_cost(a, b),
        _ => tables.default_transit_cost,
    };
    let score = weights.alpha * f64::from(latency_class) + weights.beta * f64::from(egress_cost);
    (latency_class, egress_cost, score)
}

/// Score and rank every candidate, best (lowest score) first.
///
/// Stable tie-break, per the ticket's own requirement: score, then region
/// name (`None` sorts before any `Some`), then the caller-supplied key. A
/// tie-break has to be total and deterministic or "nearest" would flap
/// between calls with no peer-set change to justify it.
pub fn rank<T, I>(
    caller: &NodeLocality,
    candidates: I,
    tables: &RouteTables,
    weights: &RouteWeights,
) -> Vec<ScoredCandidate<T>>
where
    T: Ord + Clone,
    I: IntoIterator<Item = (T, NodeLocality)>,
{
    let mut scored: Vec<ScoredCandidate<T>> = candidates
        .into_iter()
        .map(|(key, locality)| {
            let (latency_class, egress_cost, score) = score(caller, &locality, tables, weights);
            ScoredCandidate {
                key,
                locality,
                latency_class,
                egress_cost,
                score,
            }
        })
        .collect();
    scored.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.locality.region.cmp(&b.locality.region))
            .then_with(|| a.key.cmp(&b.key))
    });
    scored
}

/// The single nearest candidate, or `None` if `candidates` was empty. Callers
/// that already filtered to healthy peers get "degrade to the next-nearest
/// survivor" for free by re-calling this with one fewer candidate — there is
/// no separate fallback path to keep in sync.
pub fn pick_nearest<T, I>(
    caller: &NodeLocality,
    candidates: I,
    tables: &RouteTables,
    weights: &RouteWeights,
) -> Option<ScoredCandidate<T>>
where
    T: Ord + Clone,
    I: IntoIterator<Item = (T, NodeLocality)>,
{
    rank(caller, candidates, tables, weights).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(region: &str, provider: &str) -> NodeLocality {
        NodeLocality::new(Some(region.to_string()), Some(provider.to_string()))
    }

    #[test]
    fn same_region_same_provider_scores_zero() {
        let tables = RouteTables::defaults();
        let (lat, egress, score) = score(
            &loc("us-west", "hetzner"),
            &loc("us-west", "hetzner"),
            &tables,
            &RouteWeights::DEFAULT,
        );
        assert_eq!((lat, egress), (0, 0));
        assert_eq!(score, 0.0);
    }

    /// Verify bullet 1/2: two same-provider instances in different regions —
    /// the caller's own region always wins, deterministically, regardless of
    /// which region the caller happens to be in.
    #[test]
    fn same_provider_prefers_the_callers_own_region() {
        let tables = RouteTables::defaults();
        let candidates = vec![
            ("us-west-node", loc("us-west", "hetzner")),
            ("eu-west-node", loc("eu-west", "hetzner")),
        ];

        let from_west = pick_nearest(
            &loc("us-west", "hetzner"),
            candidates.clone(),
            &tables,
            &RouteWeights::DEFAULT,
        )
        .unwrap();
        assert_eq!(from_west.key, "us-west-node");

        let from_eu = pick_nearest(
            &loc("eu-west", "hetzner"),
            candidates,
            &tables,
            &RouteWeights::DEFAULT,
        )
        .unwrap();
        assert_eq!(from_eu.key, "eu-west-node");
    }

    /// Verify bullet 3: same-region-cross-provider loses to same-provider on
    /// egress score, even though both are latency-free.
    #[test]
    fn same_region_prefers_same_provider_over_cross_provider() {
        let tables = RouteTables::defaults();
        let winner = pick_nearest(
            &loc("us-west", "hetzner"),
            vec![
                ("hetzner-node", loc("us-west", "hetzner")),
                ("aws-node", loc("us-west", "aws")),
            ],
            &tables,
            &RouteWeights::DEFAULT,
        )
        .unwrap();
        assert_eq!(winner.key, "hetzner-node");
        assert_eq!(winner.score, 0.0);
    }

    /// Verify bullet 4: cross-region-same-provider beats same-region-
    /// cross-provider under the DEFAULT weights specifically — this is the
    /// number the module doc claims, pinned so a weight change is caught.
    #[test]
    fn default_weights_favor_same_provider_over_same_region() {
        let tables = RouteTables::defaults();
        let caller = loc("us-west", "hetzner");
        let (east_hetzner_lat, east_hetzner_egress, east_hetzner_score) =
            score(&caller, &loc("us-east", "hetzner"), &tables, &RouteWeights::DEFAULT);
        let (west_aws_lat, west_aws_egress, west_aws_score) =
            score(&caller, &loc("us-west", "aws"), &tables, &RouteWeights::DEFAULT);

        assert_eq!((east_hetzner_lat, east_hetzner_egress), (2, 0));
        assert_eq!((west_aws_lat, west_aws_egress), (0, 2));
        assert_eq!(east_hetzner_score, 2.0);
        assert_eq!(west_aws_score, 3.0);
        assert!(east_hetzner_score < west_aws_score);

        let winner = pick_nearest(
            &caller,
            vec![
                ("us-east-hetzner", loc("us-east", "hetzner")),
                ("us-west-aws", loc("us-west", "aws")),
            ],
            &tables,
            &RouteWeights::DEFAULT,
        )
        .unwrap();
        assert_eq!(winner.key, "us-east-hetzner");
    }

    /// Verify bullet 5 (the scoring half): remove the nearest candidate and
    /// the next-nearest survivor wins — degraded, not failed. The actual
    /// "still up" fact is `mesh_directory`'s job; this only checks that
    /// scoring over a smaller candidate set degrades correctly.
    #[test]
    fn removing_the_nearest_candidate_falls_back_to_next_nearest() {
        let tables = RouteTables::defaults();
        let caller = loc("us-west", "hetzner");
        let full = vec![
            ("us-west-node", loc("us-west", "hetzner")),
            ("eu-west-node", loc("eu-west", "hetzner")),
        ];
        assert_eq!(
            pick_nearest(&caller, full.clone(), &tables, &RouteWeights::DEFAULT)
                .unwrap()
                .key,
            "us-west-node"
        );

        let degraded: Vec<_> = full
            .into_iter()
            .filter(|(k, _)| *k != "us-west-node")
            .collect();
        assert_eq!(
            pick_nearest(&caller, degraded, &tables, &RouteWeights::DEFAULT)
                .unwrap()
                .key,
            "eu-west-node"
        );
    }

    #[test]
    fn empty_candidate_set_resolves_to_none() {
        let tables = RouteTables::defaults();
        let winner: Option<ScoredCandidate<&str>> = pick_nearest(
            &loc("us-west", "hetzner"),
            Vec::<(&str, NodeLocality)>::new(),
            &tables,
            &RouteWeights::DEFAULT,
        );
        assert!(winner.is_none());
    }

    #[test]
    fn unknown_region_or_provider_degrades_to_the_configured_default_not_to_free() {
        let tables = RouteTables::defaults();
        let caller = NodeLocality::default();
        let candidate = loc("us-west", "hetzner");
        let (lat, egress, _) = score(&caller, &candidate, &tables, &RouteWeights::DEFAULT);
        assert_eq!(lat, tables.default_geo_distance);
        assert_eq!(egress, tables.default_transit_cost);
    }

    #[test]
    fn r2_egress_is_free_only_when_r2_is_the_candidate_not_the_caller() {
        let tables = RouteTables::defaults();
        assert_eq!(tables.transit_cost("hetzner", "cloudflare-r2"), 0);
        // The reverse is deliberately undeclared and falls back to the
        // default — see the module doc's note on why this is directional.
        assert_eq!(
            tables.transit_cost("cloudflare-r2", "hetzner"),
            tables.default_transit_cost
        );
    }

    #[test]
    fn tie_break_is_stable_by_region_then_key() {
        let tables = RouteTables::defaults();
        // Two candidates that score identically (same region, same
        // provider as each other and as the caller) must still resolve
        // deterministically by key.
        let winner = pick_nearest(
            &loc("us-west", "hetzner"),
            vec![
                ("z-node", loc("us-west", "hetzner")),
                ("a-node", loc("us-west", "hetzner")),
            ],
            &tables,
            &RouteWeights::DEFAULT,
        )
        .unwrap();
        assert_eq!(winner.key, "a-node");
    }

    #[test]
    fn load_with_no_override_file_returns_defaults() {
        let (tables, weights) = (
            RouteTables::load(Path::new("/nonexistent/transit-cost.toml")).unwrap(),
            RouteTables::load_weights(Path::new("/nonexistent/transit-cost.toml")).unwrap(),
        );
        assert_eq!(weights, RouteWeights::DEFAULT);
        assert_eq!(tables.geo_distance("us-west", "us-east"), 2);
    }

    /// The checked-in `.yah/infra/transit-cost.toml` documents itself as
    /// staying in lockstep with [`RouteTables::defaults`] — this is what
    /// actually enforces that claim instead of leaving it to a comment. If
    /// this fails, either the file drifted from the code or vice versa; fix
    /// whichever one is wrong, don't adjust the assertions to match.
    #[test]
    fn the_checked_in_transit_cost_toml_parses_and_matches_the_built_in_defaults() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../.yah/infra/transit-cost.toml");
        let tables = RouteTables::load(&path).expect("checked-in transit-cost.toml parses");
        let weights =
            RouteTables::load_weights(&path).expect("checked-in transit-cost.toml parses");
        assert_eq!(weights, RouteWeights::DEFAULT);
        assert_eq!(tables.geo_distance("us-west", "us-east"), 2);
        assert_eq!(tables.geo_distance("us-west", "eu-west"), 4);
        assert_eq!(tables.transit_cost("hetzner", "aws"), 2);
        assert_eq!(tables.transit_cost("hetzner", "cloudflare-r2"), 0);
        assert_eq!(
            tables.transit_cost("cloudflare-r2", "hetzner"),
            tables.default_transit_cost
        );
    }

    #[test]
    fn load_applies_operator_overrides_on_top_of_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "route-score-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("transit-cost.toml");
        std::fs::write(
            &path,
            r#"
[weights]
alpha = 2.0
beta = 0.5

[[geo_distance]]
a = "us-west"
b = "us-east"
distance = 9

[[transit_cost]]
from = "hetzner"
to = "aws"
cost = 10
"#,
        )
        .unwrap();

        let tables = RouteTables::load(&path).unwrap();
        let weights = RouteTables::load_weights(&path).unwrap();

        assert_eq!(weights.alpha, 2.0);
        assert_eq!(weights.beta, 0.5);
        assert_eq!(tables.geo_distance("us-west", "us-east"), 9);
        assert_eq!(tables.transit_cost("hetzner", "aws"), 10);
        // Untouched rows keep the built-in default.
        assert_eq!(tables.geo_distance("us-west", "us-central"), 1);

        std::fs::remove_dir_all(&dir).ok();
    }
}
