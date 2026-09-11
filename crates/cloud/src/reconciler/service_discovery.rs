//! Fanout service-record discovery — read the fleet's node-local stores
//! without letting a node this read could not see read as a node with nothing
//! on it.
//!
//! R844-F4. The service-record store is **node-local** by construction: it is a
//! `tokio::watch` plus a node-local JSON ledger in
//! `oss/yubaba/crates/yubaba/src/service_records.rs`, and nothing replicates it
//! through raft. So one node's `GET /service-records?ready=true` answers for
//! that node's workloads and no others, and a reader that asks a single node
//! cannot resolve a placement whose members registered elsewhere.
//!
//! The topology chosen for that (R844-F4, over raft replication and a
//! leader-only read) is **client-side fanout with explicit partial-answer
//! semantics**: service records are a high-churn *liveness* surface refreshed
//! off a 15s sweep, not durable consensus state, so replicating them buys
//! convergence at the price of log write-amplification proportional to how
//! often workloads flap. Fanout adds no new replicated state and is therefore
//! the reversible direction.
//!
//! ## This is a liveness channel, so it speaks yubaba's liveness vocabulary
//!
//! yubaba already solved this exact reporting problem one crate up, in
//! `failure_detector.rs`, and `GET /raft/status` has been shipping the answer:
//!
//! ```text
//! "liveness": { "channel": "raft-heartbeat", "peers": {
//!    "1": { "silent_for_ms": null, "state": "unknown" },     ← a node that is DOWN
//!    "2": { "silent_for_ms": 445,  "state": "live" } } }
//! ```
//!
//! Node 1 there was us-south-001 during its 2026-09-01 host outage — genuinely
//! unreachable at every layer. It is reported `unknown`, **not** `down`, and
//! above all it is **not omitted from the map**. That is
//! [`NodeLiveness::Unknown`]'s documented rule: *"this detector cannot see the
//! node at all — not the same as 'down'"*, and the trait's companion rule that
//! an empty report means *"this detector has no view right now"*, never *"every
//! node is down"*.
//!
//! This module is the same fact on a different evidence channel, so it borrows
//! that shape rather than minting a second vocabulary for it:
//!
//! | `failure_detector` | here | the shared idea |
//! |---|---|---|
//! | `LivenessReport` — a map **total over every peer** | [`ServiceRecordFanout`] — a map **total over every asked node** | a node you could not see is an entry, never a gap |
//! | `NodeLiveness::{Live, Unknown}` + `as_str()` | [`RecordVisibility::{Answered, Unknown}`] + [`as_str`](RecordVisibility::as_str) | one lowercase wire spelling for the verdict |
//! | `FailureDetector::channel()` = `"raft-heartbeat"` | [`ServiceRecordFanout::CHANNEL`] = `"service-records"` | *what* saw the node, reported alongside the verdict |
//! | an empty report is "no view", not "all down" | an empty fanout asked nobody and claims nothing | absence of evidence is not evidence |
//!
//! It cannot literally reuse those types: `yubaba` depends on `yah-cloud`, so
//! the dependency only runs the other way. The alignment is therefore in the
//! shape and the words, which is where the cost of divergence actually lands —
//! on the operator reading two subsystems describe one fleet.
//!
//! One deliberate divergence: there is no `silent_for_ms` analogue. That field
//! pairs with `Unknown` to say "no positive evidence *yet*" from a detector
//! watching a continuous heartbeat. A discovery read is one-shot — the attempt
//! *is* the evidence — so the pairing `NodeObservation` expresses by convention
//! (`Unknown` ⇒ `silent_for_ms: None`) is expressed here in the type instead:
//! only [`RecordVisibility::Answered`] can carry records at all.
//!
//! ## The load-bearing rule
//!
//! **Absence must never render as empty**, which is the whole correctness
//! argument for choosing fanout. A union that drops non-answering nodes renders
//! a *subset* of the fleet's backends and looks successful — a front door
//! published from it points at a strictly smaller set than the operator
//! declared, with nothing in the output saying so. That is the same shape R772
//! found and reverted, and the failure R844-F3 must not inherit when it widens
//! ingress placement past cardinality one.
//!
//! Measured, not hypothetical. Fanning out across the declared nodes on
//! 2026-09-01 produced all three cases at once:
//!
//! * nodes that answered 200 with a (possibly empty) record set — *known*;
//! * us-south-001 (100.64.0.2) **unreachable at every layer** during a Vultr
//!   host failure: no ICMP to its public address, SSH closed, no ICMP on the
//!   mesh — [`UnknownReason::Unreachable`];
//! * us-west-015 (100.64.0.7), yubaba 0.8.20, answering **404** because its
//!   binary predates the endpoint — [`UnknownReason::EndpointAbsent`]. It is up
//!   and serving; it cannot answer *this question*, which is a third state
//!   again, and reading it as an empty record set would under-report the fleet.
//!
//! What a partial answer *means* is deliberately left to the caller, because it
//! differs by call site: `yah cloud apply` treats an unseen node as fatal only
//! when a rule actually failed to resolve against it (one node in this fleet is
//! documented-normal offline, so hard-failing every apply on it would cost more
//! than the bug), while a set-valued placement read must treat any gap as "the
//! set is unknown". [`ServiceRecordFanout::unknown_note`] gives both the
//! rendering they need.
//!
//! [`NodeLiveness::Unknown`]: https://docs.rs/yubaba — `yubaba::failure_detector`

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{bail, Result};

use super::ingress::{IngressPlan, IngressRule};

/// One ready service record, as the discovery read sees it over the wire.
///
/// `ports` is the *dialable* set — R844-F2's `resolved_ports` where the node
/// reports them, which is not the same as a workload's declared ports. The
/// invariant R844-F1/F2 established and this reader relies on: a record exists
/// iff yubaba declared the workload serving **and** a dialable port is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRecord {
    /// Mesh identity the record was admitted under — a bundle's workload name
    /// (`BundleSlot::workload_name`, the service name unless the slot renames
    /// it), a container's `expose.mesh.identity`.
    ///
    /// Carried because it is the only field that says *which workload* a record
    /// describes (R844-F5). Matching by port alone was enough while every rule
    /// pinned one, but a rule that declares `fronted = true` and lets discovery
    /// answer for the port has nothing else to select on — and a node runs
    /// several workloads (us-east-001 runs three), so an unkeyed read would
    /// hand back whichever of them sorted first.
    pub ident: String,
    /// Mesh address the workload bound (R599-F12 — not loopback).
    pub mesh_ip: String,
    /// Ports the record is dialable on.
    pub ports: Vec<u16>,
    /// The same dialable ports keyed by **port name** (R844-F15), off the
    /// record's `named_ports`.
    ///
    /// This is what lets [`ServiceRecordFanout::port_for`] answer for a
    /// multi-port workload at all. Empty when the answering node predates the
    /// field, which is the normal state during a fleet roll — every rule that
    /// resolved before still resolves, because the name is only consulted when
    /// the anonymous read is ambiguous.
    pub named_ports: BTreeMap<String, u16>,
}

/// Why a node's records could not be seen.
///
/// Every variant is a reason the *reader* has no view — none of them is a claim
/// about the node being down, and none is a claim that the node has no records.
/// Kept as a separate axis from the verdict for the same reason
/// `NodeObservation` keeps `silent_for_ms` beside `liveness`: the verdict is
/// what a caller branches on, the reason is what an operator acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownReason {
    /// Named by a placement but absent from `.yah/infra/machines/`, so there is
    /// no address to ask. Previously this degraded to an empty record set,
    /// which read as "the workload is not up".
    Undeclared,
    /// No answer at all: no route, connect refused, timeout, tunnel failure.
    /// Measured live on us-south-001 during a host-provider outage.
    Unreachable(String),
    /// Answered **404** at the discovery endpoint. The node is up and its
    /// yubaba is serving — it simply predates `GET /service-records` and cannot
    /// answer this question. Measured on us-west-015 (yubaba 0.8.20).
    EndpointAbsent(String),
    /// Answered, but not with an answer this reader can use: a non-2xx status,
    /// or a body that would not decode.
    BadAnswer(String),
}

impl fmt::Display for UnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Undeclared => write!(
                f,
                "is not declared in .yah/infra/machines/, so there is no address to ask"
            ),
            Self::Unreachable(detail) => write!(f, "did not answer ({detail})"),
            Self::EndpointAbsent(detail) => write!(
                f,
                "answered 404 — its yubaba predates GET /service-records, so it CANNOT answer, \
                 which is not the same as having no records ({detail})"
            ),
            Self::BadAnswer(detail) => write!(f, "answered unusably ({detail})"),
        }
    }
}

/// What this read established about one node — the discovery-channel analogue
/// of `NodeLiveness`.
///
/// Two states, not three: a discovery read either got the node's answer or it
/// did not. There is no `Suspect` here because there is no silence clock to be
/// partway along — see the module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordVisibility {
    /// The node answered. The vec may be empty — that is a **known** none, and
    /// the only shape in this module allowed to read as one.
    Answered(Vec<DiscoveredRecord>),
    /// This read could not see the node's records. Never "down", never "none".
    Unknown(UnknownReason),
}

impl RecordVisibility {
    /// Stable lowercase wire/CLI spelling, mirroring `NodeLiveness::as_str`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Answered(_) => "answered",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Records this node reported, empty for a node that could not be seen.
    ///
    /// Convenience for rendering only. Branching on this instead of on the
    /// variant is exactly the collapse this module exists to prevent.
    pub fn records(&self) -> &[DiscoveredRecord] {
        match self {
            Self::Answered(records) => records,
            Self::Unknown(_) => &[],
        }
    }

    /// Why the node could not be seen, or `None` if it answered.
    pub fn unknown_reason(&self) -> Option<&UnknownReason> {
        match self {
            Self::Answered(_) => None,
            Self::Unknown(reason) => Some(reason),
        }
    }
}

/// The result of a fanout service-record read: a map **total over every node
/// asked**, in the shape of a `LivenessReport`.
///
/// Deliberately not a flat `Vec<DiscoveredRecord>`, and deliberately not a pair
/// of "found" and "failed" lists either. The union alone cannot express the
/// difference between the fleet having no backend on a port and the reader
/// having failed to ask the node that has one, and every consumer of this data
/// degrades quietly on a short set rather than erroring. Keying by node — with
/// an unseen node *present* and marked [`RecordVisibility::Unknown`] — makes
/// that difference impossible to drop on the floor, which is precisely why
/// `GET /raft/status` reports a dead peer as an `unknown` entry instead of
/// leaving it out of `peers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRecordFanout {
    /// Every node this read asked, keyed by machine name. Ordered, so two reads
    /// of the same fleet render identically.
    pub nodes: BTreeMap<String, RecordVisibility>,
}

impl ServiceRecordFanout {
    /// Which evidence channel these verdicts come from, reported alongside them
    /// exactly as `FailureDetector::channel()` is. A reader comparing this to a
    /// `raft-heartbeat` verdict needs to know the two saw the node differently.
    pub const CHANNEL: &'static str = "service-records";

    /// Record a node's answer. An empty `records` is a valid, meaningful
    /// answer — the node is authoritative for its own workloads and says there
    /// are none.
    pub fn push_answer(&mut self, machine: impl Into<String>, records: Vec<DiscoveredRecord>) {
        self.nodes
            .insert(machine.into(), RecordVisibility::Answered(records));
    }

    /// Record that a node's records could not be seen, and why.
    pub fn push_unknown(&mut self, machine: impl Into<String>, reason: UnknownReason) {
        self.nodes
            .insert(machine.into(), RecordVisibility::Unknown(reason));
    }

    /// How many nodes the read asked.
    pub fn asked(&self) -> usize {
        self.nodes.len()
    }

    /// Nodes this read could not see, with the reason each.
    pub fn unknown(&self) -> impl Iterator<Item = (&str, &UnknownReason)> {
        self.nodes.iter().filter_map(|(machine, visibility)| {
            visibility
                .unknown_reason()
                .map(|reason| (machine.as_str(), reason))
        })
    }

    /// True when at least one asked node could not be seen — the answer is a
    /// lower bound on the fleet, not a description of it.
    pub fn is_partial(&self) -> bool {
        self.unknown().next().is_some()
    }

    /// Every record any node reported, tagged with the node that reported it.
    pub fn records(&self) -> impl Iterator<Item = (&str, &DiscoveredRecord)> {
        self.nodes.iter().flat_map(|(machine, visibility)| {
            visibility
                .records()
                .iter()
                .map(move |r| (machine.as_str(), r))
        })
    }

    /// Did this node answer?
    pub fn answered_by(&self, machine: &str) -> bool {
        matches!(
            self.nodes.get(machine),
            Some(RecordVisibility::Answered(_))
        )
    }

    /// Why one node could not be seen, if it was asked and could not be.
    pub fn unknown_reason(&self, machine: &str) -> Option<&UnknownReason> {
        self.nodes.get(machine)?.unknown_reason()
    }

    /// **Every** address to dial for one rule — one per node in scope that
    /// answered with a record on that port. Empty when none did.
    ///
    /// **Scoped to the rule's own placement when it has one.** A rule that names
    /// machines is answered only from those machines' records — otherwise a
    /// union read would happily hand back a *different* node's workload that
    /// happens to listen on the same port, and publish a hostname pointing at
    /// the wrong service. A rule with no placement falls back to the whole
    /// union, which is the fleet-wide read this module exists for.
    ///
    /// **Plural, because a placement set is plural** (R844-F3). Returning the
    /// first match was correct only while [`IngressRule`] could name one node;
    /// at horizontal scale > 1 it renders one backend out of N and the front
    /// door looks like it worked. Node-keyed order (the `BTreeMap`'s) makes the
    /// answer deterministic across runs, so two applies of an unchanged fleet
    /// render byte-identical config.
    /// **Empty for a rule whose port is still unresolved** (R844-F5). The match
    /// is by port, so there is nothing to match on until
    /// [`IngressPlan::resolve_ports`] has run — resolve ports first, and a rule
    /// that stayed portless fails once, in [`IngressRule::upstreams`], naming
    /// both halves.
    pub fn upstreams_for(&self, rule: &IngressRule) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let Some(port) = rule.port else {
            return out;
        };
        for (_, visibility) in self
            .nodes
            .iter()
            .filter(|(machine, _)| self.in_scope(rule, machine))
        {
            for record in visibility.records() {
                if record.ports.contains(&port) && !out.contains(&record.mesh_ip) {
                    out.push(record.mesh_ip.clone());
                }
            }
        }
        out
    }

    /// The port to dial for a rule that declared none — the one port `ident`'s
    /// ready records agree on across every node in the rule's scope.
    ///
    /// `None` unless the answer is unambiguous, and that strictness is the
    /// point (R844-F5). Zero matching records means the workload is not up, and
    /// two different ports mean the read cannot tell which one this hostname
    /// fronts; both are cases where guessing publishes a hostname at the wrong
    /// backend — the exact failure that stays invisible until a request 502s.
    /// An operator who needs an ambiguous case published pins `port` on the
    /// slot, and the pin always wins.
    ///
    /// **A workload with several listeners is no longer automatically ambiguous
    /// (R844-F15).** It used to be: an `http` + `metrics` workload offered two
    /// numbers with nothing to choose between them, so this returned `None` and
    /// the slot had to pin a port forever — which is the pin R844's whole line
    /// of work exists to remove. Now the records carry names, and a hostname
    /// fronts the port named [`kamaji::DEFAULT_PORT_NAME`]. That is not a guess
    /// dressed up as a rule: `http` is the name the allocator gives a sole
    /// listener and the name synthesis gives a first declared port, so it means
    /// "the one this workload serves traffic on" at every tier.
    ///
    /// The name is only consulted when the anonymous read is ambiguous, so a
    /// node that predates named ports resolves exactly as it did before, and
    /// two nodes disagreeing about which port is `http` is still `None`.
    ///
    /// Keyed on `ident` rather than on the rule's slot role: a node runs
    /// several workloads and the record is the only thing that knows which is
    /// which. The caller supplies the ident because it is a mirror-level fact
    /// (`BundleSlot::workload_name`), not something a pure plan carries.
    pub fn port_for(&self, rule: &IngressRule, ident: &str) -> Option<u16> {
        let mut candidates: Vec<u16> = Vec::new();
        let mut serving: Vec<u16> = Vec::new();
        for (_, visibility) in self
            .nodes
            .iter()
            .filter(|(machine, _)| self.in_scope(rule, machine))
        {
            for record in visibility.records().iter().filter(|r| r.ident == ident) {
                for port in &record.ports {
                    if !candidates.contains(port) {
                        candidates.push(*port);
                    }
                }
                if let Some(port) = record.named_ports.get(kamaji::DEFAULT_PORT_NAME) {
                    if !serving.contains(port) {
                        serving.push(*port);
                    }
                }
            }
        }
        // The named answer first — it is the only one that can disambiguate a
        // multi-listener workload — then the historic "exactly one port across
        // every in-scope node" rule for records that carry no names.
        match (serving.as_slice(), candidates.as_slice()) {
            ([one], _) => Some(*one),
            (_, [one]) => Some(*one),
            _ => None,
        }
    }

    /// The one `host:port` a workload registered as `ident` is dialable at, or
    /// `None` when the read cannot say unambiguously.
    ///
    /// The ident-keyed counterpart of [`upstreams_for`](Self::upstreams_for) +
    /// [`port_for`](Self::port_for), for a consumer that has an identity and no
    /// number: an inner-door mount (R870-F23) names a *unit*, and which port
    /// that unit took is precisely what the record answers. An `IngressRule`
    /// can select by port because a hostname rule carries one; a mount cannot.
    ///
    /// **Singular, where `upstreams_for` is plural, and that is a real limit
    /// rather than an oversight.** passway's route-table format carries an
    /// `upstreams` array per mount, so N backends are expressible — but an
    /// inner door proxies over loopback to a unit on *its own node*, and a unit
    /// at horizontal scale > 1 has one address per node. Handing this door the
    /// whole fleet's set would make it dial across the mesh, which is neither
    /// what the cleartext listener's safety argument assumed nor what the
    /// operator asked for. Two nodes answering with two addresses is therefore
    /// ambiguity, not load balancing, and ambiguity is `None`.
    ///
    /// Port selection follows [`port_for`](Self::port_for)'s discipline exactly
    /// — the port named [`kamaji::DEFAULT_PORT_NAME`] first, then the record's
    /// sole anonymous port — so a multi-listener unit resolves the same way at
    /// both tiers or at neither.
    pub fn address_for_ident(&self, ident: &str) -> Option<String> {
        let mut found: Vec<String> = Vec::new();
        for (_, visibility) in self.nodes.iter() {
            for record in visibility.records().iter().filter(|r| r.ident == ident) {
                let port = record
                    .named_ports
                    .get(kamaji::DEFAULT_PORT_NAME)
                    .copied()
                    .or(match record.ports.as_slice() {
                        [one] => Some(*one),
                        _ => None,
                    });
                let Some(port) = port else { continue };
                let addr = format!("{}:{port}", record.mesh_ip);
                if !found.contains(&addr) {
                    found.push(addr);
                }
            }
        }
        match found.as_slice() {
            [one] => Some(one.clone()),
            _ => None,
        }
    }

    /// Whether `machine`'s records may answer for `rule` — true for every node
    /// when the rule declares no placement.
    fn in_scope(&self, rule: &IngressRule, machine: &str) -> bool {
        rule.machines.is_empty() || rule.machines.iter().any(|m| m == machine)
    }

    /// One line naming every node this read could not see and why, or `None`
    /// when the read was complete.
    ///
    /// This is what makes a partial answer *visible*. A caller that renders a
    /// discovery result without consulting it is back to publishing a subset
    /// that looks like the whole.
    pub fn unknown_note(&self) -> Option<String> {
        let list = self
            .unknown()
            .map(|(machine, reason)| format!("{machine} {reason}"))
            .collect::<Vec<_>>();
        if list.is_empty() {
            return None;
        }
        Some(format!(
            "{} of {} node(s) on the {} channel are `unknown`, so this read is a LOWER BOUND on \
             the fleet, not a description of it: {}",
            list.len(),
            self.asked(),
            Self::CHANNEL,
            list.join("; ")
        ))
    }

    /// Why an unresolved `rule` might be an artefact of the read rather than a
    /// fact about the fleet — `None` when the read can be trusted for it.
    ///
    /// A rule whose every scoped node *answered* gets `None` even while other
    /// nodes are unknown: those nodes are authoritative for their own workloads,
    /// so their empty answers are a real "no record". An unscoped rule, or one
    /// scoped to any node this read could not see, is genuinely unknown.
    ///
    /// R844-F3: "every scoped node", not "the scoped node". One unseen member of
    /// a placement set is enough to make the rule's emptiness unknown — the
    /// backend could be exactly there — so the check is over the whole set and
    /// names the first member it could not see.
    fn uncertainty_for(&self, rule: &IngressRule) -> Option<String> {
        if !rule.machines.is_empty() {
            for scope in &rule.machines {
                if let Some(reason) = self.unknown_reason(scope) {
                    return Some(format!("the node this slot is placed on, {scope}, {reason}"));
                }
            }
            if rule.machines.iter().all(|m| self.answered_by(m)) {
                return None;
            }
        }
        self.unknown_note()
    }
}

impl IngressPlan {
    /// Fill in each rule's upstream from a fanout read, distinguishing "no such
    /// record" from "nobody could see the node".
    ///
    /// The fanout counterpart of [`IngressPlan::resolve_upstreams`], which takes
    /// a closure and therefore cannot see *why* a lookup came back empty. Both
    /// keep an explicitly pinned `upstream_host` — an operator override always
    /// wins, and it is the escape hatch for a node with no mesh plane.
    ///
    /// The two failure modes are different errors on purpose:
    ///
    /// * every node in scope answered and none had the port — the workload is
    ///   genuinely not serving, and publishing a hostname for it would advertise
    ///   a 502. Same error [`IngressPlan::resolve_upstreams`] already produced.
    /// * a node in scope could not be seen — the answer is *unknown*, and saying
    ///   "the workload is not up" would be a claim the read cannot support.
    pub fn resolve_upstreams_from(&mut self, fanout: &ServiceRecordFanout) -> Result<()> {
        for rule in &mut self.rules {
            if !rule.upstream_hosts.is_empty() {
                continue;
            }
            rule.upstream_hosts = fanout.upstreams_for(rule);
            if rule.upstream_hosts.is_empty() {
                if let Some(uncertainty) = fanout.uncertainty_for(rule) {
                    bail!(
                        "slot [providers.{}] fronted at {} resolved no upstream for port {}, but \
                         the discovery read was PARTIAL and cannot tell that apart from a record \
                         it never got to see: {uncertainty}. Absence here is UNKNOWN, not empty — \
                         re-run once those node(s) answer, or pin `upstream_host` on the slot if \
                         a node is expected to stay dark.",
                        rule.slot,
                        rule.hostname,
                        rule.port_label()
                    );
                }
            }
            // Surface the complete-read failure with the rule's own context.
            rule.upstreams()?;
        }
        Ok(())
    }

    /// Fill in each rule's port from a fanout read — the port half of
    /// [`resolve_upstreams_from`](Self::resolve_upstreams_from), and the
    /// fanout-backed counterpart of [`IngressPlan::resolve_ports`] (R844-F5).
    ///
    /// `ident` is the mesh identity the fronted workload registers under: a
    /// bundle's `BundleSlot::workload_name`, which is the service name unless
    /// the slot renames it. A record is only a candidate for a rule when its
    /// ident matches, because a node runs several workloads and a port picked
    /// off the wrong one publishes a hostname at somebody else's backend.
    ///
    /// **Run this before `resolve_upstreams_from`**: address discovery matches
    /// records by port, so a rule still missing one resolves no address either.
    /// Rules that pinned `port` are untouched — an operator pin always wins.
    ///
    /// Silent on failure by design: a rule that resolves neither port nor
    /// address is reported once by [`IngressRule::upstreams`], naming both,
    /// rather than twice in two vocabularies.
    pub fn resolve_ports_from(&mut self, fanout: &ServiceRecordFanout, ident: &str) {
        for rule in &mut self.rules {
            if rule.port.is_some() {
                continue;
            }
            rule.port = fanout.port_for(rule, ident);
        }
    }

    /// Every node this plan's rules are placed on, deduplicated, in rule order —
    /// the set a fanout discovery read must ask.
    ///
    /// Two independent widenings feed this, and both are needed for it to be the
    /// real set. R844-F4 made it a union *across rules*: an edge fronting two
    /// slots on two different nodes would otherwise be resolved entirely against
    /// the first node's records, which either fails or — worse — matches an
    /// unrelated workload of that node's on the same port. R844-F3 made each
    /// rule's own placement a set, so one slot at horizontal scale > 1
    /// contributes every node it runs on rather than the first one its
    /// `machines = [...]` list happened to name.
    pub fn workload_machines(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for machine in self.rules.iter().flat_map(|r| r.machines.iter()) {
            if !out.contains(&machine.as_str()) {
                out.push(machine.as_str());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IngressProvider;

    fn record(ip: &str, ports: &[u16]) -> DiscoveredRecord {
        named_record("yah-marketing", ip, ports)
    }

    /// A record for a named workload — what a node with several workloads
    /// reports, and what port resolution has to tell apart (R844-F5).
    fn named_record(ident: &str, ip: &str, ports: &[u16]) -> DiscoveredRecord {
        DiscoveredRecord {
            ident: ident.into(),
            mesh_ip: ip.into(),
            ports: ports.to_vec(),
            named_ports: kamaji::name_anonymous_ports(ports),
        }
    }

    /// A record whose ports the supervisor NAMED — the shape a multi-listener
    /// workload reports since R844-F14/F15, and the only one `port_for` can
    /// disambiguate.
    fn named_port_record(ident: &str, ip: &str, ports: &[(&str, u16)]) -> DiscoveredRecord {
        DiscoveredRecord {
            ident: ident.into(),
            mesh_ip: ip.into(),
            ports: ports.iter().map(|(_, p)| *p).collect(),
            named_ports: ports
                .iter()
                .map(|(n, p)| ((*n).to_string(), *p))
                .collect(),
        }
    }

    /// A rule placed on `machines` — `&[]` means "no declared placement", which
    /// falls back to the fleet-wide union.
    fn rule(hostname: &str, port: u16, machines: &[&str]) -> IngressRule {
        IngressRule {
            hostname: hostname.into(),
            port: Some(port),
            slot: "compute".into(),
            provider_id: None,
            machines: machines.iter().map(|m| m.to_string()).collect(),
            upstream_hosts: Vec::new(),
        }
    }

    fn plan(rules: Vec<IngressRule>) -> IngressPlan {
        IngressPlan {
            provider: IngressProvider::Passway,
            rules,
            front_doors: Vec::new(),
            tunnel_id: None,
            edge_provider_id: None,
            image: None,
        }
    }

    // ── the load-bearing distinction ──

    #[test]
    fn a_node_reporting_none_is_not_the_same_value_as_a_node_that_could_not_be_seen() {
        let mut reported_none = ServiceRecordFanout::default();
        reported_none.push_answer("us-east-001", Vec::new());

        let mut could_not_see = ServiceRecordFanout::default();
        could_not_see.push_unknown(
            "us-east-001",
            UnknownReason::Unreachable("connection refused".into()),
        );

        // Both yield zero records. Only one of them is a fact about the fleet.
        assert_eq!(reported_none.records().count(), 0);
        assert_eq!(could_not_see.records().count(), 0);
        assert_ne!(reported_none, could_not_see);
        assert_eq!(reported_none.nodes["us-east-001"].as_str(), "answered");
        assert_eq!(could_not_see.nodes["us-east-001"].as_str(), "unknown");
        assert!(!reported_none.is_partial());
        assert!(could_not_see.is_partial());
        assert!(reported_none.unknown_note().is_none());
        assert!(could_not_see.unknown_note().is_some());
    }

    #[test]
    fn an_unseen_node_stays_in_the_map_rather_than_dropping_out_of_it() {
        // The `GET /raft/status` rule, on this channel: a node that could not be
        // seen is an entry marked `unknown`, never a gap in the map. A caller
        // iterating a set that silently lost a member is the whole bug.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_unknown(
            "us-south-001",
            UnknownReason::Unreachable("no route to host".into()),
        );

        assert_eq!(fanout.asked(), 2);
        assert_eq!(
            fanout.nodes.keys().collect::<Vec<_>>(),
            vec!["us-east-001", "us-south-001"]
        );
        assert_eq!(fanout.nodes["us-south-001"].as_str(), "unknown");
        assert!(fanout.nodes["us-south-001"].records().is_empty());
    }

    #[test]
    fn the_three_live_cases_are_three_distinct_values() {
        // All three measured simultaneously on 2026-09-01: a node serving
        // records, a node in a host-provider outage, and a node whose yubaba
        // predates the endpoint. Collapsing any pair loses a real distinction.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_unknown(
            "us-south-001",
            UnknownReason::Unreachable("connect timed out".into()),
        );
        fanout.push_unknown(
            "us-west-015",
            UnknownReason::EndpointAbsent("GET /service-records returned 404".into()),
        );

        assert_eq!(fanout.asked(), 3);
        assert_eq!(fanout.records().count(), 1);
        assert!(matches!(
            fanout.unknown_reason("us-south-001"),
            Some(UnknownReason::Unreachable(_))
        ));
        assert!(matches!(
            fanout.unknown_reason("us-west-015"),
            Some(UnknownReason::EndpointAbsent(_))
        ));
        assert_eq!(fanout.unknown_reason("us-east-001"), None);
        assert_ne!(
            fanout.nodes["us-south-001"],
            fanout.nodes["us-west-015"],
            "an unreachable node and a node that cannot answer are different facts"
        );
    }

    #[test]
    fn a_404_is_cannot_answer_not_no_records() {
        // Measured: us-west-015 runs yubaba 0.8.20, whose binary predates the
        // endpoint. Reading its 404 as an empty record set would report the
        // fleet's backends as strictly fewer than they are.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_unknown(
            "us-west-015",
            UnknownReason::EndpointAbsent("GET /service-records?ready=true returned 404".into()),
        );
        assert!(fanout.is_partial());
        let note = fanout.unknown_note().unwrap();
        assert!(note.contains("us-west-015"), "got: {note}");
        assert!(note.contains("CANNOT answer"), "got: {note}");
        assert!(note.contains("predates"), "got: {note}");
    }

    #[test]
    fn the_note_names_the_channel_every_unseen_node_and_its_own_reason() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_unknown("us-south-001", UnknownReason::Unreachable("timed out".into()));
        fanout.push_unknown("us-west-015", UnknownReason::EndpointAbsent("404".into()));
        fanout.push_unknown("typo-node", UnknownReason::Undeclared);

        assert_eq!(fanout.asked(), 4);
        let note = fanout.unknown_note().unwrap();
        assert!(note.contains("3 of 4 node(s)"), "got: {note}");
        assert!(note.contains("service-records channel"), "got: {note}");
        for name in ["us-south-001", "us-west-015", "typo-node"] {
            assert!(note.contains(name), "got: {note}");
        }
        assert!(note.contains("timed out"), "got: {note}");
        assert!(note.contains(".yah/infra/machines/"), "got: {note}");
        assert!(!note.contains("us-east-001"), "got: {note}");
    }

    // ── the union (verify criterion 1) ──

    #[test]
    fn a_record_registered_on_one_node_resolves_through_a_read_that_asked_several() {
        // The node-local store means us-east-001 knows nothing of the workload
        // on us-west-001. A single-node read renders one of them; the union
        // renders both.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_answer("us-west-001", vec![record("100.64.0.9", &[9090])]);

        let mut p = plan(vec![
            rule("a.yah.dev", 8080, &[]),
            rule("b.yah.dev", 9090, &[]),
        ]);
        p.resolve_upstreams_from(&fanout).unwrap();
        assert_eq!(
            p.passway_upstreams().unwrap(),
            vec!["a.yah.dev=100.64.0.3:8080", "b.yah.dev=100.64.0.9:9090"]
        );
    }

    #[test]
    fn a_placed_rule_is_answered_only_from_its_own_node() {
        // Both nodes serve something on 8080. Resolving b.yah.dev from the
        // union would publish us-east-001's unrelated workload.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_answer("us-west-001", vec![record("100.64.0.9", &[8080])]);

        let mut p = plan(vec![rule("b.yah.dev", 8080, &["us-west-001"])]);
        p.resolve_upstreams_from(&fanout).unwrap();
        assert_eq!(
            p.passway_upstreams().unwrap(),
            vec!["b.yah.dev=100.64.0.9:8080"]
        );
    }

    #[test]
    fn workload_machines_is_the_deduplicated_set_the_read_must_ask() {
        let p = plan(vec![
            rule("a.yah.dev", 8080, &["us-east-001"]),
            rule("b.yah.dev", 9090, &["us-west-001"]),
            rule("c.yah.dev", 7070, &["us-east-001"]),
            rule("d.yah.dev", 6060, &[]),
        ]);
        assert_eq!(p.workload_machines(), vec!["us-east-001", "us-west-001"]);
    }

    #[test]
    fn one_rule_at_scale_two_contributes_both_its_nodes() {
        // R844-F3: the union is over each rule's own placement SET, not over one
        // node per rule. A single slot with `machines = [a, b]` must put both
        // into the fanout, or the read never asks the node holding the second
        // replica and renders a subset that looks complete.
        let p = plan(vec![rule("a.yah.dev", 8080, &["us-east-001", "us-west-001"])]);
        assert_eq!(p.workload_machines(), vec!["us-east-001", "us-west-001"]);
    }

    #[test]
    fn a_rule_at_scale_two_resolves_every_replica() {
        // The end-to-end set: two placed nodes, two answered records, two
        // rendered backends. Fails if any stage collapses to `first`.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_answer("us-west-001", vec![record("100.64.0.9", &[8080])]);

        let mut p = plan(vec![rule("a.yah.dev", 8080, &["us-east-001", "us-west-001"])]);
        p.resolve_upstreams_from(&fanout).unwrap();
        assert_eq!(
            p.rules[0].upstream_hosts,
            vec!["100.64.0.3".to_string(), "100.64.0.9".to_string()]
        );
        assert_eq!(
            p.passway_upstreams().unwrap(),
            vec!["a.yah.dev=100.64.0.3:8080", "a.yah.dev=100.64.0.9:8080"]
        );
    }

    #[test]
    fn a_placement_set_still_excludes_a_node_it_does_not_name() {
        // Scoping survives the widening: three nodes serve 8080, the rule names
        // two, and the third node's unrelated workload must not be published.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_answer("us-west-001", vec![record("100.64.0.9", &[8080])]);
        fanout.push_answer("us-south-001", vec![record("100.64.0.7", &[8080])]);

        let mut p = plan(vec![rule("a.yah.dev", 8080, &["us-east-001", "us-west-001"])]);
        p.resolve_upstreams_from(&fanout).unwrap();
        assert_eq!(
            p.rules[0].upstream_hosts,
            vec!["100.64.0.3".to_string(), "100.64.0.9".to_string()]
        );
    }

    #[test]
    fn one_unseen_member_of_a_placement_set_makes_the_answer_partial() {
        // A rule that resolved SOME of its replicas is still an incomplete
        // answer, and the reader must not report it as the whole set. Only the
        // definite case — every named node answered — may resolve silently.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_unknown("us-west-001", UnknownReason::Unreachable("timed out".into()));

        let p = plan(vec![rule("a.yah.dev", 8080, &["us-east-001", "us-west-001"])]);
        assert_eq!(
            fanout.upstreams_for(&p.rules[0]),
            vec!["100.64.0.3".to_string()],
            "the seen half still resolves"
        );
        assert!(
            fanout.is_partial(),
            "and the read reports itself as a lower bound"
        );
        assert!(fanout
            .unknown_note()
            .expect("an unseen node produces a note")
            .contains("us-west-001"));
    }

    // ── partial answers (verify criterion 2) ──

    #[test]
    fn an_unresolved_rule_on_an_unseen_node_says_unknown_not_not_up() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![record("100.64.0.3", &[8080])]);
        fanout.push_unknown(
            "us-west-002",
            UnknownReason::Unreachable("no route to host".into()),
        );

        let mut p = plan(vec![rule("b.yah.dev", 9090, &["us-west-002"])]);
        let err = p.resolve_upstreams_from(&fanout).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("PARTIAL"), "got: {msg}");
        assert!(msg.contains("UNKNOWN, not empty"), "got: {msg}");
        assert!(msg.contains("us-west-002"), "got: {msg}");
        assert!(msg.contains("no route to host"), "got: {msg}");
        // The complete-read wording would be a claim this read cannot support.
        assert!(!msg.contains("no resolved upstream address"), "got: {msg}");
    }

    #[test]
    fn an_unscoped_rule_is_unknown_while_any_node_is_unseen() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", Vec::new());
        fanout.push_unknown("us-south-001", UnknownReason::Unreachable("timed out".into()));

        let mut p = plan(vec![rule("a.yah.dev", 8080, &[])]);
        let err = p.resolve_upstreams_from(&fanout).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("PARTIAL"), "got: {msg}");
        assert!(msg.contains("us-south-001"), "got: {msg}");
    }

    #[test]
    fn a_rule_on_a_node_that_answered_still_gets_the_definite_error() {
        // us-east-001 is authoritative for its own workloads, so its empty
        // answer is a real "no record" even though another node went unseen.
        // Degrading this into "unknown" would make every apply un-actionable
        // for as long as one documented-offline node stays down.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", Vec::new());
        fanout.push_unknown("us-west-002", UnknownReason::Unreachable("offline".into()));

        let mut p = plan(vec![rule("a.yah.dev", 8080, &["us-east-001"])]);
        let err = p.resolve_upstreams_from(&fanout).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no resolved upstream address"), "got: {msg}");
        assert!(!msg.contains("PARTIAL"), "got: {msg}");
    }

    #[test]
    fn an_undeclared_placement_is_unknown_not_an_empty_answer() {
        // Previously a machine name absent from .yah/infra/machines/ returned
        // an empty record vec, indistinguishable from a live node with nothing
        // deployed.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_unknown("typo-node", UnknownReason::Undeclared);

        let mut p = plan(vec![rule("a.yah.dev", 8080, &["typo-node"])]);
        let err = p.resolve_upstreams_from(&fanout).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("PARTIAL"), "got: {msg}");
        assert!(msg.contains(".yah/infra/machines/"), "got: {msg}");
    }

    #[test]
    fn a_pinned_upstream_survives_a_read_that_saw_nothing() {
        // The escape hatch has to keep working while the fleet is dark, or a
        // partial read would block applies it has no bearing on.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_unknown("us-west-002", UnknownReason::Unreachable("offline".into()));

        let mut pinned = rule("a.yah.dev", 8080, &["us-west-002"]);
        pinned.upstream_hosts = vec!["127.0.0.1".into()];
        let mut p = plan(vec![pinned]);
        p.resolve_upstreams_from(&fanout).unwrap();
        assert_eq!(
            p.passway_upstreams().unwrap(),
            vec!["a.yah.dev=127.0.0.1:8080"]
        );
    }

    #[test]
    fn an_empty_read_asks_nobody_and_claims_nothing() {
        // `FailureDetector::observe`'s rule: an empty report means "no view
        // right now", never "every node is down".
        let fanout = ServiceRecordFanout::default();
        assert_eq!(fanout.asked(), 0);
        assert!(!fanout.is_partial());
        assert!(fanout.unknown_note().is_none());
        assert_eq!(fanout.records().count(), 0);
        assert_eq!(plan(Vec::new()).workload_machines(), Vec::<&str>::new());
    }

    // ── port resolution (R844-F5) ──

    /// The live shape, measured on us-east-001: three workloads, two of them
    /// sharing a port. A portless rule that matched on anything but the ident
    /// would front the wrong one.
    fn crowded_node() -> ServiceRecordFanout {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![
                named_record("yah-marketing", "100.64.0.3", &[43117]),
                named_record("yah-marketing-revalidate", "100.64.0.3", &[8081]),
                named_record("yah-marketing-feed", "100.64.0.3", &[8081]),
            ],
        );
        fanout
    }

    #[test]
    fn a_portless_rule_takes_the_port_its_own_record_reports() {
        let fanout = crowded_node();
        let mut portless = rule("yah.dev", 0, &["us-east-001"]);
        portless.port = None;

        let mut p = plan(vec![portless]);
        p.resolve_ports_from(&fanout, "yah-marketing");
        assert_eq!(p.rules[0].port, Some(43117));

        // …and the address then resolves against that port, end to end.
        p.resolve_upstreams_from(&fanout).unwrap();
        assert_eq!(
            p.passway_upstreams().unwrap(),
            vec!["yah.dev=100.64.0.3:43117"]
        );
    }

    #[test]
    fn a_pinned_port_is_never_overwritten_by_discovery() {
        let fanout = crowded_node();
        let mut p = plan(vec![rule("yah.dev", 8080, &["us-east-001"])]);
        p.resolve_ports_from(&fanout, "yah-marketing");
        assert_eq!(p.rules[0].port, Some(8080), "an operator pin always wins");
    }

    #[test]
    fn an_ident_nobody_reported_leaves_the_port_unresolved() {
        let fanout = crowded_node();
        let mut portless = rule("yah.dev", 0, &["us-east-001"]);
        portless.port = None;

        let mut p = plan(vec![portless]);
        p.resolve_ports_from(&fanout, "yah-marketing-preview");
        assert_eq!(p.rules[0].port, None);
        // One message, naming both unresolved halves — not a panic, not a rule
        // that publishes a hostname pointing at somebody else's workload.
        let msg = format!("{:#}", p.resolve_upstreams_from(&fanout).unwrap_err());
        assert!(msg.contains("no resolved port"), "got: {msg}");
        assert!(msg.contains("no resolved upstream address"), "got: {msg}");
    }

    #[test]
    fn two_ports_on_one_ident_is_ambiguous_rather_than_a_guess() {
        // A workload exposing several ports cannot say which one the hostname
        // fronts. Guessing publishes a front door at the wrong one and only
        // shows up as a 502 at request time; the mirror pins `port` instead.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![named_record("yah-marketing", "100.64.0.3", &[8080, 9090])],
        );
        let mut portless = rule("yah.dev", 0, &["us-east-001"]);
        portless.port = None;
        assert_eq!(fanout.port_for(&portless, "yah-marketing"), None);
    }

    /// …but a workload whose supervisor NAMED its ports is no longer ambiguous
    /// (R844-F15). `http` is the name a sole listener gets from the allocator
    /// and the name a front door publishes, so a hostname fronting an
    /// `http` + `metrics` workload resolves to `http` instead of forcing the
    /// slot to pin a port forever — which is the pin R844 exists to remove.
    #[test]
    fn a_named_serving_port_disambiguates_a_multi_listener_workload() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![named_port_record(
                "yah-marketing",
                "100.64.0.3",
                &[("http", 8080), ("metrics", 9090)],
            )],
        );
        let mut portless = rule("yah.dev", 0, &["us-east-001"]);
        portless.port = None;
        assert_eq!(fanout.port_for(&portless, "yah-marketing"), Some(8080));
    }

    /// The name buys disambiguation, not a guess. Two nodes that disagree about
    /// which port is `http` are still ambiguous — the same answer the anonymous
    /// path gives for two different ports, for the same reason.
    #[test]
    fn two_nodes_disagreeing_about_http_is_still_ambiguous() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![named_port_record(
                "yah-marketing",
                "100.64.0.3",
                &[("http", 8080), ("metrics", 9090)],
            )],
        );
        fanout.push_answer(
            "us-west-001",
            vec![named_port_record(
                "yah-marketing",
                "100.64.0.9",
                &[("http", 8081), ("metrics", 9090)],
            )],
        );
        let mut portless = rule("yah.dev", 0, &["us-east-001", "us-west-001"]);
        portless.port = None;
        assert_eq!(fanout.port_for(&portless, "yah-marketing"), None);
    }

    /// A node that predates named ports resolves exactly as it did before: the
    /// name is only consulted when the anonymous read is ambiguous, so the
    /// single-port path is untouched by any of this.
    #[test]
    fn a_record_with_no_names_still_resolves_its_single_port() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![DiscoveredRecord {
                ident: "yah-marketing".into(),
                mesh_ip: "100.64.0.3".into(),
                ports: vec![43117],
                named_ports: BTreeMap::new(),
            }],
        );
        let mut portless = rule("yah.dev", 0, &["us-east-001"]);
        portless.port = None;
        assert_eq!(fanout.port_for(&portless, "yah-marketing"), Some(43117));
    }

    #[test]
    fn a_record_on_a_node_outside_the_placement_does_not_answer() {
        // The `upstreams_for` scoping rule, applied to ports: another node's
        // workload of the same name is not this rule's backend.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-west-001",
            vec![named_record("yah-marketing", "100.64.0.9", &[43117])],
        );
        let mut portless = rule("yah.dev", 0, &["us-east-001"]);
        portless.port = None;
        assert_eq!(fanout.port_for(&portless, "yah-marketing"), None);
    }

    #[test]
    fn an_unresolved_port_resolves_no_address_either() {
        // Why ports must be resolved first: address discovery matches records
        // by port, so a portless rule has nothing to match on.
        let fanout = crowded_node();
        let mut portless = rule("yah.dev", 0, &["us-east-001"]);
        portless.port = None;
        assert!(fanout.upstreams_for(&portless).is_empty());
    }

    // ── address_for_ident (R870-F23 step 3) ─────────────────────────────────

    /// The whole point of the ident-keyed read: a node running three workloads
    /// answers for the one asked about, with the port IT took — which is the
    /// fact an inner-door mount has no other way to learn.
    #[test]
    fn an_ident_resolves_to_the_address_that_workload_registered() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![
                named_record("noisetable", "100.64.0.3", &[8080]),
                named_record("noisetable-account", "100.64.0.3", &[43117]),
                named_record("something-else", "100.64.0.3", &[9999]),
            ],
        );
        assert_eq!(
            fanout.address_for_ident("noisetable-account").as_deref(),
            Some("100.64.0.3:43117")
        );
        assert_eq!(fanout.address_for_ident("noisetable").as_deref(), Some("100.64.0.3:8080"));
        assert_eq!(fanout.address_for_ident("not-deployed"), None);
    }

    /// Two nodes answering with two addresses is ambiguity, not load
    /// balancing. An inner door proxies over loopback to a unit on its OWN
    /// node; handed the fleet's set it would dial across the mesh, which is
    /// neither what was asked for nor what the cleartext listener assumed.
    #[test]
    fn a_unit_on_two_nodes_is_ambiguous_rather_than_load_balanced() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![named_record("acct", "100.64.0.3", &[43117])]);
        fanout.push_answer("us-south-001", vec![named_record("acct", "100.64.0.4", &[43117])]);
        assert_eq!(fanout.address_for_ident("acct"), None);
    }

    /// The same workload reported by two nodes at ONE address — a duplicate
    /// read, not a second backend — still resolves. Deduplication is on the
    /// address, so re-asking a node cannot manufacture ambiguity.
    #[test]
    fn one_address_reported_twice_is_still_one_address() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![named_record("acct", "100.64.0.3", &[43117])]);
        fanout.push_answer("us-east-001-again", vec![named_record("acct", "100.64.0.3", &[43117])]);
        assert_eq!(fanout.address_for_ident("acct").as_deref(), Some("100.64.0.3:43117"));
    }

    /// A multi-listener workload resolves on its `http` name, exactly as
    /// `port_for` does — so a unit resolves the same way at both tiers or at
    /// neither. `name_anonymous_ports` refuses to name an unnamed pair, which
    /// is what makes the unnamed case ambiguous rather than a coin flip.
    #[test]
    fn a_multi_listener_unit_resolves_on_its_serving_port_name() {
        let mut named = ServiceRecordFanout::default();
        named.push_answer(
            "us-east-001",
            vec![DiscoveredRecord {
                ident: "acct".into(),
                mesh_ip: "100.64.0.3".into(),
                ports: vec![43117, 9100],
                named_ports: [("http".to_string(), 43117), ("metrics".to_string(), 9100)]
                    .into_iter()
                    .collect(),
            }],
        );
        assert_eq!(named.address_for_ident("acct").as_deref(), Some("100.64.0.3:43117"));

        let mut anonymous = ServiceRecordFanout::default();
        anonymous.push_answer(
            "us-east-001",
            vec![named_record("acct", "100.64.0.3", &[43117, 9100])],
        );
        assert_eq!(anonymous.address_for_ident("acct"), None);
    }
}
