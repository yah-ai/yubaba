//! Fleet-wide service-record peer discovery (R330-F17).
//!
//! # The gap this closes
//!
//! [`crate::service_records::ServiceRecords`] — and therefore
//! [`crate::deploy::mesh_resolve::ServiceRecordMeshState`], the only
//! production [`crate::deploy::mesh_resolve::MeshState`] impl — only ever
//! knows about workloads placed on **this** node. That is documented and
//! deliberate for the `local` locality gate (a node's registry answering for
//! itself is exactly right there), but it means a node with no local replica
//! of a service has no way to learn that OTHER nodes are running it. Nothing
//! in this workspace aggregates records across nodes today; grep for
//! `service-records` outside `service_records.rs`,
//! `deploy/mesh_resolve.rs` and this file turns up nothing that reads more
//! than one node's registry.
//!
//! This module is that aggregation, built the same way
//! [`crate::lease_renewal`] and [`crate::member_registration`] already push
//! per-node facts around: plain JSON over HTTP, not a new wire protocol, on a
//! periodic poll rather than push-on-change. See "Deliberately not the
//! gossip control plane" below for why.
//!
//! # How it works
//!
//! [`run`] loops every [`POLL_INTERVAL`]: it reads the current raft
//! membership (already fleet-wide and already carries `region`/`provider`
//! per R859-F2 — no new replicated field needed), tags itself with its own
//! member row, and for every OTHER member does a plain
//! `GET {addr}/service-records?ready=true` — the same endpoint
//! `yah cloud apply` and passway already poll. A successful fetch REPLACES
//! that peer's whole contribution to [`MeshDirectory`]; a failed one keeps
//! the peer's last-known-good contribution (best-effort, exactly
//! `lease_renewal`'s "tries again next tick" tolerance) until
//! [`STALE_AFTER`] or the peer leaves membership entirely.
//!
//! [`MeshDirectory::candidates`] is the read side: every known instance of
//! one mesh ident, across every node (including this one), each tagged with
//! its owning node's [`NodeLocality`]. [`crate::route_score`] turns that list
//! into a ranking; this module never scores anything itself.
//!
//! # Deliberately not the gossip control plane
//!
//! An earlier draft of this ticket assumed a compact-binary, push-on-change
//! gossip transport (SWIM-shaped) carrying health/capacity/peer-set. **That
//! does not exist anywhere in this codebase** — every control-plane exchange
//! in yubaba, without exception, is JSON over HTTP (`grep -rn
//! "reqwest::Client" oss/yubaba/crates/yubaba/src` — a dozen call sites, one
//! shape). Building a second, binary transport for exactly one consumer
//! would be a large, novel piece of infrastructure with no precedent to
//! measure it against, on a codebase whose one earlier attempt at a "second
//! evidence channel" ([`crate::lease_detector`], W253 §7) reused the existing
//! HTTP shape rather than inventing a new one. This module does the same:
//! polling over the endpoint that already exists, at a cadence cheap enough
//! (one small GET per peer per tick) not to need push-on-change to stay
//! under budget. If a live fleet later shows this cadence is too slow or too
//! costly, that is a measurement a follow-up ticket should make — not an
//! assumption to build a new transport against now.
//!
//! @yah:ticket(R330-F17, "Nearest-first service-to-service routing: mesh discovery surfaces region, callers prefer same-region target")
//! @yah:status(active)
//! @yah:at(2026-09-13T19:56:57Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R523)
//! @arch:see(.yah/docs/working/W059-almanac-release-feed.md)

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, warn};

use crate::raft::{YubabaNodeId, YubabaStateMachine};
use crate::route_score::NodeLocality;
use crate::service_records::{
    ServiceRecords, ServiceRecordsWire, DISCOVERY_PATH, HEALTH_READY, WIRE_VERSION,
};

/// How often [`run`] re-polls every peer. Chosen to keep one node's worth of
/// GETs (small JSON bodies, one per fleet member) well under a percent of a
/// tick's wall time on any fleet size this camp runs today; see the module
/// doc's "Deliberately not the gossip control plane" for why this is a poll
/// and not a push.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Timeout on one peer's fetch. Short — a slow peer should not hold up the
/// rest of the tick's polls, and a missed tick is tolerated (see
/// [`STALE_AFTER`]) rather than retried inline.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// A peer that has been unreachable for longer than this AND has left raft
/// membership is dropped from the directory entirely. A peer still IN
/// membership keeps its last-known-good entry indefinitely on the theory that
/// a live member merely slow to answer this tick will answer the next one —
/// evicting it on one missed poll would make the directory flap under
/// ordinary network jitter.
pub const STALE_AFTER: Duration = Duration::from_secs(120);

/// One instance of a mesh ident, on one node, tagged with that node's
/// locality — the unit [`crate::route_score::rank`] scores.
#[derive(Debug, Clone)]
pub struct PeerCandidate {
    /// The raft-membership address of the node this instance runs on —
    /// doubles as the tie-break key `route_score::rank` sorts by.
    pub node_addr: String,
    pub locality: NodeLocality,
    pub mesh_ip: Ipv4Addr,
    pub ports: std::collections::BTreeMap<String, u16>,
    /// Always `true` for a remote candidate (fetched via `?ready=true`); may
    /// be `false` for a local one — see [`local_candidates`].
    pub ready: bool,
}

struct PeerEntry {
    fetched_at: Instant,
    by_ident: HashMap<String, Vec<PeerCandidate>>,
}

/// Fleet-wide, region/provider-tagged service-record directory. One instance
/// lives on `ServerState` and is populated by [`run`]; readers call
/// [`Self::candidates`] and [`Self::self_locality`].
pub struct MeshDirectory {
    self_locality: RwLock<NodeLocality>,
    peers: RwLock<HashMap<String, PeerEntry>>,
}

impl Default for MeshDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshDirectory {
    pub fn new() -> Self {
        Self {
            self_locality: RwLock::new(NodeLocality::default()),
            peers: RwLock::new(HashMap::new()),
        }
    }

    /// This node's own (region, provider), as last read from its raft member
    /// row. `NodeLocality::default()` (both `None`) before the first poll
    /// tick, or on a node with no raft membership at all — callers degrade
    /// that to [`crate::route_score::RouteTables`]'s configured defaults,
    /// never to "free" or "local".
    pub fn self_locality(&self) -> NodeLocality {
        self.self_locality.read().unwrap().clone()
    }

    /// Every known instance of `ident`, across every node this directory has
    /// an entry for (including this one). Unordered — callers score and rank
    /// via [`crate::route_score`].
    pub fn candidates(&self, ident: &str) -> Vec<PeerCandidate> {
        self.peers
            .read()
            .unwrap()
            .values()
            .filter_map(|p| p.by_ident.get(ident))
            .flatten()
            .cloned()
            .collect()
    }

    /// `pub(crate)` — [`run`] is the only production caller, but
    /// `deploy::mesh_resolve`'s tests need to seed a directory directly
    /// (there is no live poll loop in a unit test), so this stays visible
    /// crate-wide rather than gated behind `#[cfg(test)]`.
    pub(crate) fn set_self_locality(&self, loc: NodeLocality) {
        *self.self_locality.write().unwrap() = loc;
    }

    /// Replace one peer's (or this node's own) whole contribution. Called
    /// after every successful fetch/read — a peer that fails this tick simply
    /// isn't called, so its previous entry survives untouched.
    pub(crate) fn ingest(&self, node_addr: String, by_ident: HashMap<String, Vec<PeerCandidate>>) {
        self.peers.write().unwrap().insert(
            node_addr,
            PeerEntry {
                fetched_at: Instant::now(),
                by_ident,
            },
        );
    }

    /// Drop any entry that is BOTH no longer in `current_members` AND older
    /// than [`STALE_AFTER`] — see the constant's doc for why both conditions
    /// have to hold.
    fn prune_departed(&self, current_members: &HashSet<String>) {
        let mut peers = self.peers.write().unwrap();
        peers.retain(|addr, entry| {
            current_members.contains(addr) || entry.fetched_at.elapsed() < STALE_AFTER
        });
    }
}

/// Build this node's own contribution directly from its local
/// [`ServiceRecords`] — no network hop needed, since it is the same process.
///
/// Unlike a remote fetch, this includes NOT-ready records too (`ready:
/// false`), preserving [`crate::deploy::mesh_resolve::MeshState::lookup`]'s
/// "presence, not readiness" contract for a co-located dependency — the one
/// case that contract's existing tests actually exercise.
fn local_candidates(
    records: &ServiceRecords,
    locality: &NodeLocality,
    self_addr: &str,
) -> HashMap<String, Vec<PeerCandidate>> {
    let mut by_ident: HashMap<String, Vec<PeerCandidate>> = HashMap::new();
    for record in records.snapshot().values() {
        by_ident
            .entry(record.ident.0.clone())
            .or_default()
            .push(PeerCandidate {
                node_addr: self_addr.to_string(),
                locality: locality.clone(),
                mesh_ip: record.mesh_ip,
                ports: record.dialable_ports().clone(),
                ready: record.is_ready(),
            });
    }
    by_ident
}

/// Turn one peer's `GET /service-records?ready=true` response into its
/// directory contribution. Pure — split out of [`fetch_peer`] so the parsing
/// and tagging logic is testable without a live HTTP server.
fn candidates_from_wire(
    wire: &ServiceRecordsWire,
    locality: &NodeLocality,
    peer_addr: &str,
) -> HashMap<String, Vec<PeerCandidate>> {
    let mut by_ident: HashMap<String, Vec<PeerCandidate>> = HashMap::new();
    for record in &wire.records {
        // Belt-and-suspenders: `?ready=true` should already guarantee this,
        // but a directory that silently routed to a not-ready remote record
        // on a server-side filter bug would be exactly the "nearest
        // including dead" failure this ticket exists to prevent.
        if record.health != HEALTH_READY {
            continue;
        }
        let ports = if record.named_ports.is_empty() {
            kamaji::name_anonymous_ports(&record.ports)
        } else {
            record.named_ports.clone()
        };
        by_ident
            .entry(record.ident.clone())
            .or_default()
            .push(PeerCandidate {
                node_addr: peer_addr.to_string(),
                locality: locality.clone(),
                mesh_ip: record.mesh_ip,
                ports,
                ready: true,
            });
    }
    by_ident
}

/// Fetch and parse one peer's service records. `Err` covers unreachable,
/// timed out, non-2xx, undecodable, or an unrecognized [`WIRE_VERSION`] —
/// every case [`run`] treats identically (keep the peer's last-known-good
/// entry and try again next tick).
async fn fetch_peer(
    client: &reqwest::Client,
    addr: &str,
    locality: &NodeLocality,
) -> Result<HashMap<String, Vec<PeerCandidate>>, String> {
    let url = format!("http://{addr}{DISCOVERY_PATH}?ready=true");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: {}", resp.status()));
    }
    let wire: ServiceRecordsWire = resp
        .json()
        .await
        .map_err(|e| format!("GET {url}: decoding: {e}"))?;
    if wire.version != WIRE_VERSION {
        return Err(format!(
            "GET {url}: unrecognized wire version {} (expected {WIRE_VERSION})",
            wire.version
        ));
    }
    Ok(candidates_from_wire(&wire, locality, addr))
}

/// Spawn this node's mesh-directory poll loop. Runs for the life of the
/// process; abort the returned handle to stop it early.
pub fn spawn(
    node_id: YubabaNodeId,
    state_machine: YubabaStateMachine,
    service_records: Arc<ServiceRecords>,
    directory: Arc<MeshDirectory>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(node_id, state_machine, service_records, directory).await;
    })
}

async fn run(
    node_id: YubabaNodeId,
    state_machine: YubabaStateMachine,
    service_records: Arc<ServiceRecords>,
    directory: Arc<MeshDirectory>,
) {
    let client = match reqwest::Client::builder().timeout(FETCH_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            warn!("mesh directory: could not build HTTP client, not polling: {e}");
            return;
        }
    };

    loop {
        let members = state_machine.members();
        let self_row = members.get(&node_id);
        let self_locality = NodeLocality::new(
            self_row.and_then(|m| m.region.clone()),
            self_row.and_then(|m| m.provider.clone()),
        );
        directory.set_self_locality(self_locality.clone());

        let self_addr = self_row
            .map(|m| m.addr.clone())
            .unwrap_or_else(|| format!("self:{node_id}"));
        directory.ingest(
            self_addr.clone(),
            local_candidates(&service_records, &self_locality, &self_addr),
        );

        let mut current_addrs: HashSet<String> =
            members.values().map(|m| m.addr.clone()).collect();
        current_addrs.insert(self_addr);

        for (peer_id, member) in members.iter() {
            if *peer_id == node_id {
                continue;
            }
            let locality = NodeLocality::new(member.region.clone(), member.provider.clone());
            match fetch_peer(&client, &member.addr, &locality).await {
                Ok(by_ident) => directory.ingest(member.addr.clone(), by_ident),
                Err(e) => debug!(
                    addr = %member.addr,
                    error = %e,
                    "mesh directory: peer fetch failed, keeping last-known-good"
                ),
            }
        }

        directory.prune_departed(&current_addrs);
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_records::ServiceRecordWire;

    fn loc(region: &str, provider: &str) -> NodeLocality {
        NodeLocality::new(Some(region.to_string()), Some(provider.to_string()))
    }

    fn wire_record(ident: &str, mesh_ip: &str, port: u16) -> ServiceRecordWire {
        ServiceRecordWire {
            ident: ident.to_string(),
            mesh_ip: mesh_ip.parse().unwrap(),
            ports: vec![port],
            named_ports: BTreeMap::from([("http".to_string(), port)]),
            resolved_ports: vec![],
            endpoints: vec![format!("{mesh_ip}:{port}")],
            named_endpoints: BTreeMap::from([("http".to_string(), format!("{mesh_ip}:{port}"))]),
            container_id: "c1".to_string(),
            health: HEALTH_READY.to_string(),
            reason: None,
            observed_at_unix_ms: 0,
        }
    }

    use std::collections::BTreeMap;

    #[test]
    fn candidates_from_wire_tags_every_record_with_the_peers_locality() {
        let wire = ServiceRecordsWire {
            version: WIRE_VERSION,
            records: vec![wire_record("noisetable", "100.64.0.2", 8080)],
        };
        let by_ident = candidates_from_wire(&wire, &loc("us-east", "hetzner"), "100.64.0.2:7443");
        let candidates = by_ident.get("noisetable").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].locality, loc("us-east", "hetzner"));
        assert_eq!(candidates[0].node_addr, "100.64.0.2:7443");
        assert!(candidates[0].ready);
        assert_eq!(candidates[0].mesh_ip.to_string(), "100.64.0.2");
        assert_eq!(candidates[0].ports.get("http"), Some(&8080));
    }

    #[test]
    fn candidates_from_wire_skips_a_record_whose_health_disagrees_with_ready_true() {
        let mut not_ready = wire_record("stale", "100.64.0.3", 9000);
        not_ready.health = "not-ready".to_string();
        let wire = ServiceRecordsWire {
            version: WIRE_VERSION,
            records: vec![not_ready],
        };
        let by_ident = candidates_from_wire(&wire, &loc("us-west", "hetzner"), "100.64.0.3:7443");
        assert!(by_ident.get("stale").is_none());
    }

    #[test]
    fn candidates_from_wire_names_anonymous_ports_when_the_peer_predates_named_ports() {
        let mut record = wire_record("legacy", "100.64.0.4", 8080);
        record.named_ports.clear();
        let wire = ServiceRecordsWire {
            version: WIRE_VERSION,
            records: vec![record],
        };
        let by_ident = candidates_from_wire(&wire, &loc("us-west", "hetzner"), "100.64.0.4:7443");
        assert_eq!(
            by_ident.get("legacy").unwrap()[0].ports.get("http"),
            Some(&8080)
        );
    }

    #[test]
    fn directory_merges_local_and_remote_contributions_for_one_ident() {
        let directory = MeshDirectory::new();
        directory.set_self_locality(loc("us-west", "hetzner"));
        directory.ingest(
            "self".to_string(),
            HashMap::from([(
                "noisetable".to_string(),
                vec![PeerCandidate {
                    node_addr: "self".to_string(),
                    locality: loc("us-west", "hetzner"),
                    mesh_ip: "100.64.0.1".parse().unwrap(),
                    ports: BTreeMap::from([("http".to_string(), 8080)]),
                    ready: true,
                }],
            )]),
        );
        directory.ingest(
            "100.64.0.2:7443".to_string(),
            HashMap::from([(
                "noisetable".to_string(),
                vec![PeerCandidate {
                    node_addr: "100.64.0.2:7443".to_string(),
                    locality: loc("eu-west", "hetzner"),
                    mesh_ip: "100.64.0.2".parse().unwrap(),
                    ports: BTreeMap::from([("http".to_string(), 8080)]),
                    ready: true,
                }],
            )]),
        );

        let candidates = directory.candidates("noisetable");
        assert_eq!(candidates.len(), 2);
        let regions: HashSet<_> = candidates
            .iter()
            .map(|c| c.locality.region.clone())
            .collect();
        assert_eq!(
            regions,
            HashSet::from([Some("us-west".to_string()), Some("eu-west".to_string())])
        );
    }

    #[test]
    fn a_peer_that_leaves_membership_and_goes_stale_is_pruned() {
        let directory = MeshDirectory::new();
        directory.ingest("gone".to_string(), HashMap::new());
        // Still a member: pruning must NOT remove it even though it is not
        // in `current_members`'s "fresh enough" branch — membership presence
        // alone keeps it.
        directory.prune_departed(&HashSet::from(["gone".to_string()]));
        assert!(directory.peers.read().unwrap().contains_key("gone"));

        // No longer a member AND (in real time) past STALE_AFTER would be
        // pruned; here we simulate "no longer a member" with an empty
        // membership set and confirm removal — the freshness half is timing-
        // dependent and covered by inspection of `prune_departed`'s logic
        // rather than a sleep-based test.
        let directory2 = MeshDirectory::new();
        directory2.peers.write().unwrap().insert(
            "gone".to_string(),
            PeerEntry {
                fetched_at: Instant::now() - STALE_AFTER - Duration::from_secs(1),
                by_ident: HashMap::new(),
            },
        );
        directory2.prune_departed(&HashSet::new());
        assert!(!directory2.peers.read().unwrap().contains_key("gone"));
    }

    #[test]
    fn removing_a_workload_from_a_peer_drops_it_on_the_next_successful_fetch() {
        // Simulates verify bullet 5 at the directory layer: a peer that used
        // to serve an ident and now doesn't (undeployed, or simply not
        // returned by a fresh `?ready=true` fetch) has its OLD contribution
        // wholesale-replaced by the new (empty-for-that-ident) one.
        let directory = MeshDirectory::new();
        directory.ingest(
            "100.64.0.2:7443".to_string(),
            HashMap::from([(
                "noisetable".to_string(),
                vec![PeerCandidate {
                    node_addr: "100.64.0.2:7443".to_string(),
                    locality: loc("us-west", "hetzner"),
                    mesh_ip: "100.64.0.2".parse().unwrap(),
                    ports: BTreeMap::new(),
                    ready: true,
                }],
            )]),
        );
        assert_eq!(directory.candidates("noisetable").len(), 1);

        // Fresh fetch no longer names the ident at all.
        directory.ingest("100.64.0.2:7443".to_string(), HashMap::new());
        assert_eq!(directory.candidates("noisetable").len(), 0);
    }
}
