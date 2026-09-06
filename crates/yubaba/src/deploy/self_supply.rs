//! `supply = "self"` provisioning and the node's requirement graph — R860-T6 /
//! W338 §"Design", §"Each member keeps its own mesh identity", §"Placement
//! consequences" 4.
//!
//! A `supply = "self"` requirement carries its provider's whole spec inline in
//! [`Requirement::provides`]. This module answers the three questions the deploy
//! handler, the destroy handler and the drain handler each ask about that:
//!
//! - **What must I stand up first?** [`self_supplied_providers`].
//! - **What dies with me?** [`self_supplied_idents`] — `self` edges only. A
//!   `wait` provider belongs to whoever declared it, and cascading into one
//!   would delete another operator's workload.
//! - **May I be drained off this node?** [`group_blocking_drain`], over the
//!   placement groups recorded in [`DeployedRequirements`].
//!
//! # Each member keeps its own mesh identity
//!
//! The load-bearing constraint (W338). Nothing here collapses a group under one
//! identity: a provider is deployed by re-entering the ordinary deploy handler
//! with its own spec, so it gets its own admission check, its own secret
//! materialization, its own archetype-registry entry and its own service record
//! — exactly what an independently-discoverable provider needs, and exactly what
//! makes the `anywhere` case expressible at all. A group is a set of edges in
//! the graph, never a new addressable object.

use std::collections::HashMap;

use workload_spec::{Locality, Supply, WorkloadSpec};

/// What a live workload's requirement edges committed this node to, recorded on
/// a successful deploy and dropped on destroy (R860-T6).
///
/// This is the "group membership plumbed to the node process" the R860-T4
/// handoff named as missing: placement computes a group camp-side, but until
/// this existed the node knew only per-workload archetypes, so `drain_workloads`
/// would happily drain a Server that a `local` edge binds to an Appliance.
///
/// Two fields and not one, because the two questions have different answers and
/// conflating them is precisely the W338 §"Placement consequences" 4 mistake:
/// teardown follows **`self` edges only**, while drainability is computed over
/// the **whole placement group** (any `local` edge, whatever its supply).
#[derive(Debug, Clone, Default)]
pub struct DeployedRequirements {
    /// Mesh idents this workload stood up itself. Torn down with it.
    pub self_supplied: Vec<String>,

    /// Member specs of this workload's placement group — the transitive closure
    /// of `local` edges, requirer first (`cloud::config::placement_group`).
    /// Held as specs because `cloud::config::group_is_drainable` is a predicate
    /// over specs, and re-deriving archetypes from idents would need a spec
    /// lookup the node does not have.
    pub group: Vec<WorkloadSpec>,
}

/// The provider specs a workload carries inline and must stand up itself, in
/// declaration order.
///
/// Read via [`WorkloadSpec::effective_requirements`] rather than `requires`
/// directly — a bare `depends_on` entry folds in as `anywhere` + `wait` and so
/// can never appear here, but going through the one supported accessor is what
/// keeps that true if the fold ever changes.
///
/// `validate::shape` guarantees every [`Supply::SelfProvision`] requirement has
/// a `provides`, that its `expose.mesh.identity` equals the requirement's ident,
/// and that the provider does not itself self-provision — so the returned specs
/// are deployable as-is and the recursion is bounded at one level.
pub fn self_supplied_providers(spec: &WorkloadSpec) -> Vec<WorkloadSpec> {
    spec.effective_requirements()
        .into_iter()
        .filter(|req| req.supply == Supply::SelfProvision)
        .filter_map(|req| req.provides.map(|boxed| *boxed))
        .collect()
}

/// The mesh idents of [`self_supplied_providers`] — what a teardown of `spec`
/// must cascade into.
///
/// **`wait` edges are never included**, at any locality. That is the whole
/// content of W338 §"Placement consequences" 4: a `wait` requirement names a
/// provider *someone else* declared and deployed, so following it on teardown
/// would delete a workload this requirer never owned.
pub fn self_supplied_idents(spec: &WorkloadSpec) -> Vec<String> {
    self_supplied_providers(spec)
        .into_iter()
        .map(|provider| provider.expose.mesh.identity.0)
        .collect()
}

/// This node's view of a workload's placement group: the workload itself,
/// followed by the `local` providers it carries inline (R860-T6, W338).
///
/// The node-side counterpart of `cloud::config::placement_group`, and
/// deliberately *not* a second implementation of its traversal. That function
/// resolves a requirement ident two ways — the inline [`Requirement::provides`]
/// spec, or a lookup against the declared `.yah/infra/workloads/` inventory —
/// and a node holds no such inventory, so only the first arm can ever fire here.
/// With the inventory empty its transitive closure degenerates to exactly this
/// list: `provides` nesting is bounded at depth 1 by `validate::shape`, and a
/// carried provider's own `local` + `wait` idents resolve to nothing.
///
/// The cost is stated where placement states it: a `local` member declared in
/// some other file is skipped, so its drain protection stays camp-side, where
/// the inventory that names it lives.
pub fn local_group_members(spec: &WorkloadSpec) -> Vec<WorkloadSpec> {
    let mut members = vec![spec.clone()];
    for req in spec.effective_requirements() {
        if req.locality != Locality::Local {
            continue;
        }
        if let Some(provider) = req.provides {
            let provider = *provider;
            if members
                .iter()
                .any(|m| m.expose.mesh.identity == provider.expose.mesh.identity)
            {
                continue;
            }
            members.push(provider);
        }
    }
    members
}

/// The requirer whose placement group forbids draining `ident` off this node,
/// or `None` when nothing does (W338 §"Placement consequences" 2).
///
/// Scans both directions on purpose, because a group binds symmetrically:
/// `ident` may be the *requirer* of a group holding an Appliance, or a
/// *provider* pulled into an Appliance requirer's group by a `local` edge. Both
/// are the same failure — draining one member alone breaks the group the same
/// way placing it alone would — and only a membership scan catches the second.
///
/// The drainability predicate itself is [`workload_spec::group_is_drainable`],
/// deliberately not reimplemented here: placement (camp-side) and drain
/// (node-side) answering that question differently is the exact drift this
/// plumbing exists to close. R860-T4's handoff said to call
/// `cloud::config::group_is_drainable` because "yubaba already depends on
/// cloud" — it does not; `cloud` is a **dev-dependency** of yubaba, and cloud's
/// own manifest records that the reverse edge was avoided on purpose (R374-F3).
/// So the body moved down to `workload-spec`, which both crates already depend
/// on, and `cloud::config::group_is_drainable` now delegates to it.
///
/// Ties broken by lowest requirer ident so the reason logged for a skipped
/// workload is stable across runs rather than a `HashMap` iteration accident.
pub fn group_blocking_drain(
    graph: &HashMap<String, DeployedRequirements>,
    ident: &str,
) -> Option<String> {
    graph
        .iter()
        .filter(|(_, deployed)| {
            deployed
                .group
                .iter()
                .any(|member| member.expose.mesh.identity.0 == ident)
                && !workload_spec::group_is_drainable(&deployed.group)
        })
        .map(|(requirer, _)| requirer.clone())
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{ImageRef, LifecycleArchetype, MeshIdent, Requirement, TierTag};

    fn spec(ident: &str) -> WorkloadSpec {
        let mut s = WorkloadSpec::for_forge(
            "fixture",
            ImageRef {
                registry: "localhost".into(),
                repository: "test".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            TierTag("infra".into()),
            vec![8080],
        );
        s.expose.mesh.identity = MeshIdent(ident.into());
        s.archetype = Some(LifecycleArchetype::Server);
        s
    }

    fn requires(ident: &str, locality: Locality, provides: Option<WorkloadSpec>) -> Requirement {
        Requirement {
            ident: MeshIdent(ident.into()),
            locality,
            supply: if provides.is_some() {
                Supply::SelfProvision
            } else {
                Supply::Wait
            },
            provides: provides.map(Box::new),
        }
    }

    /// The distinction the teardown cascade turns on: a carried provider is
    /// this workload's to stand up and to reap, a waited-on one is not.
    #[test]
    fn only_self_supplied_requirements_carry_a_provider() {
        let mut requirer = spec("headscale");
        requirer.requires = vec![
            requires("headscale-replicator", Locality::Local, Some(spec("headscale-replicator"))),
            requires("headscale-db", Locality::PreferLocal, None),
        ];
        requirer.depends_on = vec![MeshIdent("some-legacy-dep".into())];

        assert_eq!(
            self_supplied_idents(&requirer),
            vec!["headscale-replicator".to_string()],
            "a wait requirement and a legacy depends_on entry must never be cascaded into"
        );
    }

    /// A `self` provider at any locality is still this workload's to reap —
    /// locality answers *where*, supply answers *whose*.
    #[test]
    fn a_self_supplied_provider_is_owned_at_every_locality() {
        for locality in [Locality::Local, Locality::PreferLocal, Locality::Anywhere] {
            let mut requirer = spec("app");
            requirer.requires = vec![requires("sidecar", locality, Some(spec("sidecar")))];
            assert_eq!(self_supplied_idents(&requirer), vec!["sidecar".to_string()]);
        }
    }

    #[test]
    fn a_workload_with_no_requirements_supplies_nothing() {
        assert!(self_supplied_providers(&spec("plain")).is_empty());
    }

    /// The inherited R860-T4 gap, at the predicate the node now consults: a
    /// Server bound to an Appliance by a `local` edge is not drainable, and it
    /// is named by the requirer whose group holds it.
    #[test]
    fn a_server_in_an_appliance_group_is_not_drainable_from_either_direction() {
        let mut appliance = spec("headscale");
        appliance.archetype = Some(LifecycleArchetype::Appliance);
        let replicator = spec("headscale-replicator");
        let group = vec![appliance, replicator];

        let mut graph = HashMap::new();
        graph.insert(
            "headscale".to_string(),
            DeployedRequirements {
                self_supplied: vec!["headscale-replicator".into()],
                group,
            },
        );

        assert_eq!(
            group_blocking_drain(&graph, "headscale-replicator").as_deref(),
            Some("headscale"),
            "the provider is only reachable by scanning group MEMBERSHIP, not group keys"
        );
        assert_eq!(
            group_blocking_drain(&graph, "headscale").as_deref(),
            Some("headscale"),
            "the requirer's own group holds an appliance — itself"
        );
        assert_eq!(
            group_blocking_drain(&graph, "unrelated"), None,
            "a workload in no group must stay drainable"
        );
    }

    /// An all-Server group drains normally: the predicate refuses on the
    /// Appliance archetype, not on group membership as such.
    #[test]
    fn an_all_server_group_stays_drainable() {
        let mut graph = HashMap::new();
        graph.insert(
            "app".to_string(),
            DeployedRequirements {
                self_supplied: vec!["sidecar".into()],
                group: vec![spec("app"), spec("sidecar")],
            },
        );
        assert_eq!(group_blocking_drain(&graph, "sidecar"), None);
        assert_eq!(group_blocking_drain(&graph, "app"), None);
    }
}
