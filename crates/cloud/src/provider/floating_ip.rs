//! Provider-abstracted floating/reserved-IP mobility (R594-F5).
//!
//! [`FloatingIpProvider`] is the domain-level trait each vendor adapter
//! (`HetznerFloatingIp`, `OvhFloatingIp`, `VultrFloatingIp` — sibling
//! modules in this directory) implements. [`reconcile_assignment`] is the
//! shared idempotent + zone-checked core all three run through, so the
//! "no-op when already assigned" / "reject a cross-zone move" behavior is
//! written and tested exactly once instead of three times.
//!
//! [`on_ingress_owner_changed`] is the Rust-level callable entry point for
//! R594-F5's ask: given the raft `ingress_owner` seam
//! (`oss/yubaba/crates/yubaba/src/raft/mod.rs`'s `YubabaRequest::SetIngressOwner`
//! / `ClearIngressOwner`, `RaftAppState::ingress_owner`) and the machine it
//! currently names, command the provider floating IP to follow. Wiring
//! this to fire *automatically* whenever `ingress_owner` transitions lives
//! in the raft-apply / leadership-reconcile path
//! (`oss/yubaba/crates/yubaba/src/leader.rs`), which is peer-owned and
//! off-limits to this ticket — see [`on_ingress_owner_changed`]'s doc
//! comment for the exact call site a follow-up should add. This is the
//! same "mechanism now, wiring later" shape R594-F3 used for service
//! records.
//!
//! This mirrors, at the sovereign-ingress tier, the "external identity
//! follows placement" property [R591](yah://arch/symbol/R591) names for
//! Headscale via a Cloudflare Tunnel. R591 is peer-owned and gated on R570
//! (real multi-node raft HA); this module is not blocked on either — it
//! builds directly on the `ingress_owner` seam, which already exists.
//!
//! @yah:ticket(R859-F2, "Wire floating-ip.* provider adapters to ingress_owner transitions + health-checked DNS withdrawal for dead origins")
//! @yah:at(2026-09-05T10:22:42Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R859)
//! @yah:next("The verbs and adapters exist with zero callers: envoy/floating_ip.rs + provider/{vultr,hetzner,ovh}_floating_ip.rs are dead code today. Raft already holds and applies ingress_owner (raft/mod.rs:597,1182) — the missing piece is the effector that commands the provider when it changes, which is exactly W267 Tier 1's 'external identity follows placement' (the R591 property).")
//! @yah:next("Two failover speeds, both currently manual: intra-provider = floating-IP reassign (seconds, no DNS propagation, no cert re-mint — mind the W267-verified mobility constraints: Hetzner per network zone, OVH per DC region, Vultr region-bound); cross-provider = short-TTL DNS withdrawal of the dead origin's A record (needs R859-F1's rendering).")
//! @yah:next("The health signal for withdrawal must NOT come from raft health (W267 §'Where liveness lives' — reachability is observer-relative); use the supervisor-level fact only: a machine leaving the fleet / its yubaba unreachable from quorum, not a per-proxy probe.")
//! @yah:next("cloud.mesh_failover (W271) is the existing manual verb — keep it as the operator path; this ticket automates the effector both paths share.")
//! @yah:next("Tier: Wizard — touches live-fleet failover semantics; wrong wiring here turns a leadership flap into a public outage. Design the guard rails (hysteresis, refuse-on-degraded-quorum per yubaba-failover.md) before the effector.")
//! @yah:handoff("LANDED, uncommitted. Six pieces. (1) THE BLOCKER, fixed as decided: MemberInfo and YubabaRequest::SetMember each gained machine: Option<String> with #[serde(default)] (oss/yubaba/crates/yubaba/src/raft/mod.rs), written by member_registration from leader::derive_machine_name() — the SAME function that writes ingress_owner, so the two strings are comparable by construction. Accessors YubabaStateMachine::machine_for_node / node_for_machine at raft/store.rs:769. (2) quorum_health.rs (new, oss/yubaba/crates/yubaba/src/): pure judge_quorum(voters, LivenessReport) -> QuorumVerdict{Healthy{voters,available,margin} | Degraded{reason} | Unknown{reason}} + permits_withdrawal(); thin caller wired into scheduler.rs's tick loop where both inputs are already in hand. (3) cloud::provider::floating_ip gained the registry R594-F5 left out: floating_ip_provider_for(&MachineConfig), provider_has_floating_ip_adapter(&str), and one FLOATING_IP_PROVIDERS table both read so they cannot drift. (4) All three adapters registered in envoy.rs default_adapters() — floating_ip.assign/status are now genuinely dispatchable. (5) MachineConfig.ingress_floating_ip: Option<String> (config.rs, beside `cloudflared`) + cloud::validate::check_ingress_floating_ip, wired into `yah cloud validate` (error) and the apply preflight (warning), same split as R605-F12. (6) DNS withdrawal through F1's EXISTING seam: public_origins gained a health_excluded arg and returns ResolvedOrigins{origins, health_withdrawn}; DomainPasswayPlan gained health_withdrawn; diff_apex_records prunes a health-withdrawn address regardless of origins_complete.")
//! @yah:handoff("THE DEPENDENCY FORK, resolved with evidence, and the answer is NOT the one the brief's criterion predicts. Read both manifests: oss/yubaba/crates/cloud/Cargo.toml has NO yubaba dep, and oss/yubaba/crates/yubaba/Cargo.toml already carries `cloud = { package = \"yah-cloud\", path = \"../cloud\" }` — but under [dev-dependencies]. So a runtime yubaba -> cloud edge would create NO cargo cycle. I did not take it anyway, and the reason is a documented architectural rule the brief's cycle-check could not see: cloud/Cargo.toml's `local-driver` dep comment records that local-driver was carved out of cloud in R374-F3 SPECIFICALLY \"so yubaba could own MinIO lifecycle without a reverse yubaba->cloud dep\". Adding that edge would put velveteen, velveteen-exec, yah-hetzner, yah-mesofact-bundle and yah-almanac into the release daemon shipped to every fleet node — an architecture call outside a courier's blast radius. So I took the SECOND branch: plan_ingress_owner_effect() is pure, fully tested, and UNWIRED. Everything else in the ticket ships.")
//! @yah:handoff("WHERE THE PLANNER LIVES, and why there. plan_ingress_owner_effect is in cloud (provider/floating_ip.rs), not yubaba, because its inputs include MachineConfig and its outputs command cloud adapters. The two yubaba-side facts cross the boundary AS PLAIN DATA, never as types: OwnerLiveness{ConfirmedUp,ConfirmedDown,Unconfirmed} re-spells TransitionTracker::committed, and QuorumHealth{Healthy,Degraded{reason}} re-spells QuorumVerdict (its Unknown collapses into Degraded — both refuse, and the distinction survives in the reason string). That honours decision 7: raft stays read-only from the cloud side, and no dep edge is created in either direction. Signature: plan_ingress_owner_effect(previous_owner, current_owner, current_owner_liveness, &quorum, machines) -> IngressOwnerEffect{Reassign{machine,ip_id} | Withdraw{machine,reason} | Refuse{reason} | NoOp{reason}}. NoOp carries a reason (the brief wrote it bare) because a log line saying which of the five no-op paths was taken is worth six characters. The two action variants ARE W267's two failover speeds: Reassign is intra-provider, Withdraw feeds public_origins' health_excluded set for the cross-provider path — which is what gives the enum's fourth variant real work rather than a placeholder.")
//! @yah:gotcha("READ THIS BEFORE ATTACHING THE EFFECTOR — the identity bridge is narrower than its name. `ingress_owner` and the new `MemberInfo.machine` both carry `/etc/hostname` (leader::derive_machine_name), which is NOT reliably the .yah/infra/machines/<name>.toml name. Evidence, not inference: app/yah/cli/src/mesh.rs:108's R858-T3 gotcha states it outright, and R841's incident record (app/yah/cli/src/rollout/executor.rs) has ingress_owner holding `vps-4c1efa56` for the box declared `us-west-001`. The brief's decided fix assumed these were machine names; they are not, and I corrected the field's doc comment rather than shipping a plausible-looking lie. What the bridge DOES guarantee is exact: node_id <-> ingress_owner, because both strings come from one derivation. Resolving that string to a MachineConfig is a SEPARATE, fail-loud step — cloud::provider::floating_ip::resolve_ingress_owner matches declared names EXACTLY (no prefix match, no fuzzy fallback, no \"it is probably the only public-ip box\") and refuses by name, listing every declared machine and explaining the hostname mismatch. Pinned by an_ingress_owner_that_names_no_declared_machine_refuses_loudly. So on today's fleet a us-west-001 flip would REFUSE rather than misfire. Closing it properly means renaming hostnames to match machine names, or adding a declared hostname alias to MachineConfig — separable work, not R859-F2's.")
//! @yah:handoff("TWO DESIGN CALLS I MADE THAT ARE NOT IN THE BRIEF, both forced by a test that failed. (a) `Degraded` means A VOTER IS DOWN, not \"this topology has no redundancy\". My first judge_quorum keyed purely on margin and my own 1-voter test failed it: a rig has zero margin at its healthiest, so a margin-only rule calls its best possible state degraded and refuses every withdrawal forever — an inert feature wearing the costume of a safety check. Rule is now `Degraded` iff available < majority, OR available == majority AND available < voters. A fully-available cluster is Healthy at any size with margin stating the slack honestly. Pinned by an_intact_two_voter_cluster_is_healthy_but_a_three_voter_one_reduced_to_two_is_not — identical `available`, opposite verdicts, because one lost a voter and the other did not. (b) The empty-apex guard in plan_domain_passway is checked against the origins that SURVIVE health exclusion, which makes it the health failover's backstop for free: if every declared front door is confirmed down, plan_domain_passway refuses. \"All our front doors are down\" must never render as \"withdraw every A record\" — a dead origin still in DNS is a partial outage, an empty apex is a total one. The health withdrawal is therefore capped at all-but-the-last origin by construction, with no second rule to keep in sync. Same reasoning one level finer: an address a SURVIVING origin still answers on is dropped from health_withdrawn (two machines can share a floating IP).")
//! @yah:handoff("THE origins_complete x health CROSS-PRODUCT, decided and tested as four cells (health_withdrawal_and_declaration_completeness_are_independent). complete+healthy -> prune. complete+down -> prune. incomplete+healthy -> withheld_prune. incomplete+down -> PRUNE ANYWAY. The bottom-right cell is the whole point and it is a judgement, so here is the reasoning: origins_complete=false protects against mistaking an ABSENCE for a withdrawal, and a health withdrawal is not an absence — it is a positive observation about a machine the collation resolved, taint-checked and address-checked on the way into health_withdrawn. An unrelated service's broken TOML is not evidence about a box we watched go down; letting it veto the prune would leave a dead origin taking its share of the round-robin for as long as that typo lives. Fail-closed-on-withdrawal is NOT weakened: the gate on a health withdrawal is the QUORUM verdict, applied one layer up in plan_ingress_owner_effect, which refuses to emit the exclusion at all out of a degraded quorum. Two withdrawal paths, each fail-closed on the evidence actually relevant to it. Also tested: an_incomplete_collation_prunes_only_the_health_withdrawn_surplus (both reasons coexist in one diff — health-excluded pruned, merely-absent still withheld). Decisions 1, 8 and 9 held as written: TransitionTracker/HysteresisPolicy reused with no new debounce type; no TTL parameter anywhere and a doc comment saying why so the next reader does not re-open it; cloud.mesh_failover untouched and the planner cannot transfer leadership.")
//! @yah:verify("Baselines measured BEFORE any edit, on this tree. cloud (`cargo test --manifest-path oss/yubaba/crates/cloud/Cargo.toml --features json-schema`): 1124 passed / 0 failed / 4 ignored (lib) + 3/0/1 + 2/0/0 + 0/0/1. yubaba (`--manifest-path oss/yubaba/crates/yubaba/Cargo.toml --lib`): 708 passed / 0 failed. `cargo build --workspace`: GREEN before I started — it was not already red, so nothing here is inherited. AFTER: cloud 1152 / 0 / 4 (+28, same other three targets); yubaba lib 724 / 0 / 0 (+16); `cargo build --workspace` green; `cargo check --manifest-path oss/yubaba/Cargo.toml --all-targets` clean (covers the two integration-test files I touched). Epoch gate: `RUSTC_WRAPPER='' cargo run -p xtask -- cluster-epochs` GREEN — both axes were red from my raft/mod.rs + raft/store.rs edits, verdict NOT BREAKING on both, hashes re-recorded, cluster_protocol stays 5 and state_epoch stays 4, with a full why_not_a_bump entry in cluster-epochs.json surface_rerecords[2026-09-05]. Both drifted surfaces were verified to contain ONLY my hunks (git diff -U0: store.rs is one 47-line insertion) before writing, so no peer's unanalysed change was swept into a verdict. `scripts/check-workload-spec-ts.sh`: ok.")
//! @yah:gotcha("scripts/check-schema-drift.sh is RED, and it is NOT this ticket's drift. The gate regenerates and then `git diff --quiet -- .yah/schema`, so it fails for ANY uncommitted regeneration, in sync or not — exactly the condition R860-T1 already recorded (\"both gates go red for that reason; a pathspec commit of the generated paths was attempted and DENIED by the approval gate\"). It was red before I started (.yah/schema/{machine,workload}.toml.schema.json were both already dirty in the tree at session start). I ran `cargo run -p xtask -- emit-schemas` as required — MachineConfig gained a field — and machine.toml.schema.json:77 now carries `ingress_floating_ip`. Note the regen ALSO shrank workload.toml.schema.json's WorkloadSpec description, because R860-T1's @yah: annotations have since left workload-spec/src/lib.rs; that is a correct regeneration of a generated artifact, not damage, and any peer running the same command gets the same output. The gate goes green when those two paths are committed. I did not commit (instructed not to).")
//! @yah:gotcha("OVH's floating-IP adapter is now REGISTERED but is NOT live-ready, and registering it was still right. ovh_floating_ip.rs's own module doc records that its auth is a placeholder — OVH signs with an application key + secret + consumer key + timestamped HMAC, not the bare `X-Ovh-Consumer` header the adapter sends. Registering it in default_adapters() makes the verb dispatchable (the latent bug decision 4 names); it does not make it correct against api.ovh.com. All three registrations are gated on their credential being present via fob::get_or_env, so the adapter is absent from every camp that has not deliberately set `ovh-consumer-key`/$OVH_CONSUMER_KEY. Swap in real OVH request signing before pointing it at anything live. Checked rather than assumed: HetznerEnvoy (cloud.vps.*) and HetznerFloatingIp (floating_ip.*) share the adapter id \"hetzner\" but claim DISJOINT verb sets, and agent-tools/src/envoy_tools.rs:214 groups by VERB id rather than adapter id — so neither shadows the other, and the per-verb `provider` enum still gets three distinct choices.")
//! @yah:next("ATTACHING THE EFFECTOR is the one genuine operator/architecture call left, and it is the cycle question the brief anticipated — just with a different answer than \"cycle: yes/no\". There is no cargo cycle; there IS a documented rule (R374-F3, recorded in cloud/Cargo.toml's local-driver comment) against a runtime yubaba -> cloud edge, and taking it would put velveteen/velveteen-exec/yah-hetzner/yah-mesofact-bundle/yah-almanac into the fleet daemon. Three options for whoever decides: (a) accept the edge and call plan_ingress_owner_effect from scheduler.rs:370's tick loop, which already computes is_leader, owns the TransitionTracker, and now computes the quorum verdict — the call site is ready and the three facts it needs are all in scope there; (b) extract the floating-IP provider trait + adapters into a small crate both depend on, the same move R374-F3 made for local-driver; (c) leave it operator-driven and expose the planner through a cloud verb. Nothing else in this ticket is blocked on the answer — the decision logic and every gate are landed and tested either way.")
//! @yah:next("Two follow-ups worth their own tickets, both genuinely separable rather than deferred work I was standing on. (1) The hostname vs machine-name gap (see gotcha): today an ingress_owner of `vps-4c1efa56` REFUSES loudly instead of misfiring, which is safe but means the effector is inert on any box whose /etc/hostname differs from its declared name. Fix is either renaming those hostnames or adding a declared hostname alias to MachineConfig that resolve_ingress_owner also matches — a fleet-config decision, not a code one. (2) Real OVH request signing (application key + secret + consumer key + timestamped HMAC) before the ovh floating_ip.* verbs touch api.ovh.com.")
//! @yah:handoff("FILES (all uncommitted; tree anchor f086233d, the commit this session started from — quote that SHA, not HEAD, in any restore instruction). yubaba: raft/mod.rs (field on MemberInfo + SetMember, apply arm, 3 new tests), raft/store.rs:769 (machine_for_node/node_for_machine), quorum_health.rs (NEW, 12 tests), lib.rs (module decl), scheduler.rs (judge_quorum caller + debug! import), member_registration.rs (machine param through spawn/run/plan_registration/write_row, 3 new tests, 12 existing call sites updated), leader.rs (derive_machine_name now pub, doc), main.rs (passes it), leader_pin.rs + headroom.rs (MemberInfo literals), tests/raft_tenant_placement.rs, yubaba-test-harness/src/solo_node.rs (per-node stand-in name — /etc/hostname would make every in-process node identical and node_for_machine ambiguous), cluster-epochs.json. cloud: provider/floating_ip.rs (registry + planner + resolver + 14 tests), provider/mod.rs (re-exports), envoy.rs (default_adapters), config.rs (ingress_floating_ip + 4 test literals), validate.rs (check_ingress_floating_ip + 8 tests), reconciler/domain.rs (ResolvedOrigins, health_withdrawn, diff rule, 5 new tests), plus mechanical `ingress_floating_ip: None,` in 10 more files' MachineConfig literals. app/yah/cli/src/cloud.rs: lint wired at both sites + tally. .yah/schema/{machine,workload}.toml.schema.json regenerated. COLLISION CHECK: envoy.rs has 5 hunks and only ONE is mine (default_adapters); the other four are R859-F1's known_verb_descriptors work — expected, not a collision. I did not touch the foreign hunks the brief named (proc_control.rs, topology.rs, cloud.rs's header) and no unexpected diffs appeared in any file I own.")
//! @yah:handoff("LEADER SIGN-OFF, independently verified by a separate session that re-ran every gate and traced each claim to file:line — not taken on the implementer's word. Commands: cloud tests EXIT=0 at 1152 passed / 0 failed / 4 ignored (baseline 1124/0/4 after R859-F1, +28); yubaba --lib EXIT=0 at 724/0 (baseline 708/0, +16); cargo build --workspace EXIT=0; cargo check oss/yubaba --all-targets EXIT=0. Confirmed in code: MemberInfo.machine and SetMember.machine are Option<String> with #[serde(default)] (raft/mod.rs:1159, :352) — the rollout-safety property, pinned by a_pre_r859_f2_snapshot_loads_untagged_and_a_downgrade_reads_a_tagged_one (:1612) and a_pre_r859_f2_set_member_still_applies_with_no_machine (:1651), so a live cluster's existing JSON snapshot still deserializes. judge_quorum (quorum_health.rs:154) is pure, Degraded requires a voter actually down, a 1-voter rig reads Healthy, and scheduler.rs:445 feeds it real voter_ids() plus the raft LivenessReport rather than fabricated data. Withdrawal and reassign are refused on Degraded (floating_ip.rs:509, :529) while upserts and tenant placement stay ungated — the same fail-closed-on-withdrawal / fail-open-on-addition rule R859-F1 established for its prune gate, now applied consistently across both children. The four-cell cross-product is tested in health_withdrawal_and_declaration_completeness_are_independent (domain.rs:1673), and diff_apex_records (:833) remains the SOLE prune path, so withdrawal went through F1's existing public_origins -> plan_domain_passway seam with no parallel route to DNS mutation. Registry, the three default_adapters() registrations, unknown-provider bail (floating_ip.rs:238), ingress_floating_ip lint wiring (cloud.rs:9641/:10735) with absent-config as a clean skip (validate.rs:770), and TransitionTracker/HysteresisPolicy reuse with no second debounce all verify.")
//! @yah:handoff("Tree anchor at handoff: f086233d6b092de2f32cafad5e0010494078269c — the shared tree as I left it. Diff against it (`git diff f086233d6b092de2f32cafad5e0010494078269c..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:gotcha("check-schema-drift.sh exits 1, and it is NOT this relay's drift. Verified by hashing .yah/schema/*.json before and after: the script's own regeneration produces byte-identical files, so the gate is red purely on its `git diff --quiet` uncommitted-artifact condition — R860-T1's recorded state, independently corroborated by an unrelated session's gotcha at topology.rs:67. Nothing was changed. Note the uncommitted schema diff is MIXED: machine.toml.schema.json:77 carries this ticket's own regenerated ingress_floating_ip entry alongside R860's description churn, so whoever commits must not assume the whole diff is theirs.")
//! @yah:assumes("QuorumVerdict::Unknown -> QuorumHealth::Degraded is documented but has no conversion code yet. That is consistent with plan_ingress_owner_effect being unwired — the collapse only becomes reachable when the effector is attached — but it is the first thing to implement if it is.")
//! @yah:handoff("DELIVERED BUT UNWIRED, and this is the relay's one genuine operator call. plan_ingress_owner_effect() landed pure, fully tested, and with no production caller: inputs are (previous ingress_owner, current ingress_owner, quorum verdict, hysteresis verdict, machine configs), output is an action enum. scheduler.rs's call site is prepared and already computes the quorum verdict the effector would need, so attaching it is a small change — but it is not a courier's call to make. There is NO cargo cycle today (cloud has no yubaba dep; yubaba depends on cloud only under [dev-dependencies], Cargo.toml:152). What blocks it is a deliberate architectural decision, not a technical impossibility: cloud/Cargo.toml:75-78's `local-driver` comment records R374-F3 carving that crate out SPECIFICALLY to avoid a reverse yubaba->cloud dependency, and taking that edge would pull velveteen/hetzner/mesofact/almanac into the fleet daemon. Reversing a documented carve-out is an operator decision, so everything else in the ticket shipped and this one seam waits on an answer.")
//! @yah:gotcha("PREMISE CORRECTION, found by the implementer against a claim the Leader's dispatch had asserted — the dispatch said to populate the new machine tag from derive_machine_name(), assuming it yields the .yah/infra/machines/<name>.toml name. It does not: it reads /etc/hostname (leader.rs:876-884), exactly as app/yah/cli/src/mesh.rs:108 already states, and R841's incident record has ingress_owner holding `vps-4c1efa56` for the box declared `us-west-001`. The bridge is still exact where it matters, because node_id and ingress_owner come from ONE derivation — but turning that string into a MachineConfig is now a separate fail-loud step, resolve_ingress_owner (floating_ip.rs:383), which refuses by exact name rather than guessing (test at :887). On today's fleet an ingress_owner flip would therefore REFUSE rather than misfire — correct, but it means the floating-IP path is inert until hostnames and machine-TOML names are reconciled. That reconciliation is not in this relay.")

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

use crate::config::MachineConfig;

/// One provider's floating/reserved-IP transport + mobility policy.
///
/// Implementors: [`super::hetzner_floating_ip::HetznerFloatingIp`],
/// [`super::ovh_floating_ip::OvhFloatingIp`],
/// [`super::vultr_floating_ip::VultrFloatingIp`].
#[async_trait]
pub trait FloatingIpProvider: Send + Sync {
    /// Provider id, e.g. `"hetzner"` — matches [`MachineConfig::provider`].
    fn id(&self) -> &'static str;

    /// Resolve a target machine into this provider's native attach
    /// identifier (server id / serviceName / instance UUID) plus the
    /// mobility zone it lives in. May hit the provider's API (e.g. a
    /// name→id lookup) — this is a live-data resolution step, not a pure
    /// function of the TOML.
    async fn resolve_target(&self, machine: &MachineConfig) -> Result<FloatingIpTarget>;

    /// Current state of the floating/reserved IP: its home zone (fixed for
    /// the IP's lifetime) and the provider-native id of whatever it's
    /// attached to right now, if anything.
    async fn current_assignment(&self, ip_id: &str) -> Result<FloatingIpState>;

    /// Actually move the IP. Callers (namely [`reconcile_assignment`])
    /// have already checked idempotency and zone match before calling
    /// this — it always issues the provider call.
    async fn reassign(&self, ip_id: &str, target: &FloatingIpTarget) -> Result<()>;
}

/// A resolved reassign target: provider-native attach id + the mobility
/// zone it lives in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloatingIpTarget {
    /// Hetzner numeric server id, OVH serviceName, or Vultr instance UUID.
    pub attach_id: String,
    /// Hetzner network zone / OVH datacentre-region / Vultr region.
    pub zone: String,
}

/// Current provider-side state of a floating/reserved IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloatingIpState {
    /// The IP's home mobility zone — fixed for its lifetime.
    pub zone: String,
    /// Provider-native id of whatever it's attached to right now, if
    /// anything.
    pub attached_to: Option<String>,
}

/// Outcome of [`reconcile_assignment`] / [`on_ingress_owner_changed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloatingIpAssignOutcome {
    /// `true` iff a reassign call was actually issued.
    pub reassigned: bool,
    /// The attach target the IP now points at.
    pub attached_to: String,
}

/// Idempotent, zone-checked core shared by every provider adapter and by
/// [`on_ingress_owner_changed`].
///
/// 1. Fetch the floating IP's current home zone + attachment.
/// 2. Refuse a cross-zone move (Hetzner/OVH/Vultr all physically cannot
///    move an IP outside its mobility zone — W267 §Tier 1) *before*
///    issuing any reassign call.
/// 3. If the current attachment already equals `target`, return
///    `reassigned: false` without calling [`FloatingIpProvider::reassign`]
///    — the ownership-flip fixture this ticket verifies against relies on
///    this short-circuit to prove "re-applying the same owner drives ZERO
///    reassign calls."
/// 4. Otherwise call [`FloatingIpProvider::reassign`] and report
///    `reassigned: true`.
pub async fn reconcile_assignment(
    provider: &dyn FloatingIpProvider,
    ip_id: &str,
    target: &FloatingIpTarget,
) -> Result<FloatingIpAssignOutcome> {
    let current = provider.current_assignment(ip_id).await?;
    if current.zone != target.zone {
        bail!(
            "floating_ip.assign: {} ip {ip_id:?} is homed to zone {:?}, cannot move it into zone {:?} (target attach id {:?}) — {} floating/reserved IPs are not mobile across zones (W267 §Tier 1)",
            provider.id(),
            current.zone,
            target.zone,
            target.attach_id,
            provider.id(),
        );
    }
    if current.attached_to.as_deref() == Some(target.attach_id.as_str()) {
        return Ok(FloatingIpAssignOutcome {
            reassigned: false,
            attached_to: target.attach_id.clone(),
        });
    }
    provider.reassign(ip_id, target).await?;
    Ok(FloatingIpAssignOutcome {
        reassigned: true,
        attached_to: target.attach_id.clone(),
    })
}

/// Callable entry point: react to the raft `ingress_owner` seam naming
/// `machine` as the box that now owns public ingress, by commanding
/// `ip_id` to follow it.
///
/// **Wiring (not done here — deliberately out of scope, see the ticket's
/// hard constraints):** the raft apply loop
/// (`oss/yubaba/crates/yubaba/src/raft/mod.rs::apply`) already mutates
/// `RaftAppState::ingress_owner` on `YubabaRequest::SetIngressOwner` /
/// `ClearIngressOwner`. A follow-up ticket should call this function from
/// the leadership/reconcile path (`oss/yubaba/crates/yubaba/src/leader.rs`
/// — peer-owned, not touched here) at the point where it observes
/// `ingress_owner` transition from `old` to `Some(new_machine)`: look up
/// `new_machine`'s [`MachineConfig`] (already available there via
/// `WorkspaceConfig`), pick the [`FloatingIpProvider`] matching
/// `machine.provider`, and call
/// `on_ingress_owner_changed(provider, &machine, ip_id).await`. `ip_id`
/// itself (which floating IP is "the" ingress IP) has no home today —
/// that's a small config surface (likely a field alongside the
/// `public-ip` taint R572-F3 is adding) a follow-up should introduce
/// alongside the wiring, not invented speculatively here.
///
/// `ClearIngressOwner` (`ingress_owner` going to `None`) has no defined
/// action yet — there is no "detach the IP" verb because Tier 1 has no
/// specified safe-unassigned state (leaving the IP on the last-known-good
/// node is arguably the correct default). Extend when that need
/// materializes; until then this function is only meaningful for
/// `Some(machine)` transitions.
pub async fn on_ingress_owner_changed(
    provider: &dyn FloatingIpProvider,
    machine: &MachineConfig,
    ip_id: &str,
) -> Result<FloatingIpAssignOutcome> {
    let target = provider.resolve_target(machine).await?;
    reconcile_assignment(provider, ip_id, &target).await
}

// ── R859-F2: the registry ─────────────────────────────────────────────────

/// Which providers ship a [`FloatingIpProvider`] adapter, and the credential
/// each one authenticates with — `(provider id, vault slot, env fallback)`.
///
/// One table rather than a `match` arm per consumer, because two questions read
/// it and they must not drift: [`floating_ip_provider_for`] builds the adapter,
/// and [`provider_has_floating_ip_adapter`] answers the same question *without*
/// credentials, for `yah cloud validate` (which runs on an operator's laptop
/// with no fleet tokens loaded and must still be able to refuse a machine
/// declaring a floating IP its provider cannot move).
const FLOATING_IP_PROVIDERS: &[(&str, &str, &str)] = &[
    ("hetzner", "hetzner-api-token", "HETZNER_API_TOKEN"),
    ("ovh", "ovh-consumer-key", "OVH_CONSUMER_KEY"),
    ("vultr", "vultr-api-key", "VULTR_API_KEY"),
];

/// Does `provider` have a floating-IP adapter at all?
///
/// Credential-free by design — see [`FLOATING_IP_PROVIDERS`]. A `false` here
/// means [`MachineConfig::ingress_floating_ip`] on such a machine could never
/// be acted on, which is a declaration worth refusing at validate time rather
/// than discovering during a failover.
pub fn provider_has_floating_ip_adapter(provider: &str) -> bool {
    FLOATING_IP_PROVIDERS.iter().any(|(id, _, _)| *id == provider)
}

/// Resolve `machine.provider` to a live [`FloatingIpProvider`] — the registry
/// R594-F5 left out.
///
/// Without this the three adapters were unreachable from any caller holding a
/// [`MachineConfig`]: each knows its own wire format, and nothing mapped a
/// declared provider onto one. Credentials come from the same
/// `fob`-then-env source [`super::HetznerDriver::from_default_sources`] uses,
/// so a camp that can already drive a provider can drive its floating IPs with
/// no extra configuration.
///
/// Two distinct failures, kept distinct because they want different fixes: a
/// provider with no adapter is a *declaration* error (nothing will ever move
/// that IP), while a missing credential is an *environment* error (the
/// declaration is fine, this process cannot act on it).
pub fn floating_ip_provider_for(machine: &MachineConfig) -> Result<Box<dyn FloatingIpProvider>> {
    let Some((_, slot, env)) = FLOATING_IP_PROVIDERS
        .iter()
        .find(|(id, _, _)| *id == machine.provider)
    else {
        bail!(
            "machine {:?} declares provider {:?}, which has no floating-IP adapter — \
             floating/reserved IPs are implemented for {} only",
            machine.name,
            machine.provider,
            FLOATING_IP_PROVIDERS
                .iter()
                .map(|(id, _, _)| *id)
                .collect::<Vec<_>>()
                .join(", "),
        );
    };
    let token = fob::get_or_env(slot, env)
        .with_context(|| format!("reading {slot} for machine {:?}", machine.name))?
        .with_context(|| {
            format!(
                "machine {:?} needs {:?} credentials to move its floating IP, but neither the \
                 `{slot}` vault slot nor ${env} is set",
                machine.name, machine.provider,
            )
        })?;
    Ok(match machine.provider.as_str() {
        "hetzner" => Box::new(super::HetznerFloatingIp::new(token)),
        "ovh" => Box::new(super::OvhFloatingIp::new(token)),
        "vultr" => Box::new(super::VultrFloatingIp::new(token)),
        // Unreachable: the lookup above already refused anything not in the
        // table. Kept as a loud bail rather than an `unreachable!` so adding a
        // row to the table without a constructor here is a runtime error naming
        // the omission, not a panic in a failover path.
        other => bail!("floating-ip registry: no constructor wired for provider {other:?}"),
    })
}

// ── R859-F2: the pure ingress-owner effect planner ────────────────────────

/// What a `TransitionTracker`-style hysteresis says about one machine, crossed
/// into this crate as plain data.
///
/// The yubaba-side original is
/// `yubaba::lease_detector::TransitionTracker::committed`, which answers
/// `Option<Confirmed>`. It is re-spelled rather than imported because
/// `cloud` does not depend on `yubaba` and must not start to — this module's
/// header records that raft is **read-only from the cloud side**, and a type
/// dependency is not a read. The crossing is by value, over the existing
/// read-only surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerLiveness {
    /// The hysteresis has committed this machine as up.
    ConfirmedUp,
    /// The hysteresis has committed this machine as down — the only value that
    /// is positive evidence *against* a machine.
    ConfirmedDown,
    /// Never dwelled long enough in either direction to be committed: a
    /// freshly-elected leader's tracker, a node mid-flap, or no detector at
    /// all. **Not** the same as down.
    Unconfirmed,
}

/// Live consensus health, crossed into this crate as plain data.
///
/// The yubaba-side original is `yubaba::quorum_health::QuorumVerdict`, whose
/// `Unknown` variant collapses into [`Degraded`](Self::Degraded) here: both
/// refuse a withdrawal, and the distinction survives in the reason string. Same
/// no-type-dependency rule as [`OwnerLiveness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumHealth {
    Healthy,
    Degraded {
        /// The yubaba-side `QuorumVerdict::reason()`, carried verbatim so a
        /// refusal names the actual voter counts rather than a generic excuse.
        reason: String,
    },
}

/// What should happen to public ingress, given an `ingress_owner` observation.
///
/// The two failover speeds W267 §Tier 1 names appear here as two variants:
/// [`Reassign`](Self::Reassign) is the intra-provider one (seconds, no DNS
/// propagation, no cert re-mint), [`Withdraw`](Self::Withdraw) the
/// cross-provider one (pull the dead origin's A record and let the survivors
/// take its share).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressOwnerEffect {
    /// Move `ip_id` onto `machine` — the intra-provider failover.
    Reassign {
        /// The machine that now owns public ingress.
        machine: String,
        /// Its [`MachineConfig::ingress_floating_ip`].
        ip_id: String,
    },
    /// Drop `machine` from the apex origin set — the cross-provider failover.
    ///
    /// Consumed by
    /// [`public_origins`](crate::reconciler::domain::public_origins)'s
    /// health-exclusion argument, which is why this carries a machine name and
    /// not a record id: the DNS layer already knows how to turn a declared
    /// machine into an address, and duplicating that here would be a second
    /// answer to a question R859-F1 settled.
    Withdraw {
        machine: String,
        reason: String,
    },
    /// Do nothing, and refuse to do it — positive grounds against acting.
    ///
    /// Distinct from [`NoOp`](Self::NoOp) because it is worth *saying*: a
    /// refusal means the world is in a state where the correct action is known
    /// and deliberately not taken, which an operator watching a failover needs
    /// to see. A `NoOp` is not news.
    Refuse { reason: String },
    /// Nothing to do.
    NoOp { reason: String },
}

impl IngressOwnerEffect {
    /// `true` for the two variants that command something.
    pub fn is_action(&self) -> bool {
        matches!(self, Self::Reassign { .. } | Self::Withdraw { .. })
    }

    /// One operator-readable line, for a log or a `yah cloud apply` summary.
    pub fn reason(&self) -> String {
        match self {
            Self::Reassign { machine, ip_id } => {
                format!("reassign floating IP {ip_id} to {machine}")
            }
            Self::Withdraw { machine, reason } => {
                format!("withdraw {machine} from the apex: {reason}")
            }
            Self::Refuse { reason } | Self::NoOp { reason } => reason.clone(),
        }
    }
}

/// Resolve an `ingress_owner` string to the machine it names.
///
/// **This cannot assume the string is a `.yah/infra/machines/` name.**
/// `ingress_owner` is written from yubaba's `derive_machine_name()`, which
/// reads `/etc/hostname`; R841's incident record has it holding
/// `vps-4c1efa56` for the box declared as `us-west-001`, and
/// `app/yah/cli/src/mesh.rs`'s R858-T3 gotcha states the mismatch outright.
/// So the resolution is an exact match against declared names and **nothing
/// else** — no prefix match, no fuzzy fallback, no "it is probably the only
/// public-ip box". A wrong guess here reassigns a live public IP onto the
/// wrong machine, which is the outage R859-F2 exists to prevent, so an
/// unresolvable owner is a refusal that names both sides.
pub fn resolve_ingress_owner<'a>(
    owner: &str,
    machines: &'a [MachineConfig],
) -> Result<&'a MachineConfig> {
    machines
        .iter()
        .find(|m| m.name == owner)
        .with_context(|| {
            format!(
                "raft names {owner:?} as the ingress owner, but no .yah/infra/machines/*.toml \
                 declares a machine with that name (declared: {}). Note `ingress_owner` carries \
                 the node's /etc/hostname, which is not always its machine name — R841 saw \
                 `vps-4c1efa56` recorded for the box declared as `us-west-001`. Rename the box's \
                 hostname to match its machine name, or this mapping cannot be made safely.",
                machines
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        })
}

/// Decide what public ingress should do about an `ingress_owner` observation —
/// pure, so the decision is testable as arithmetic and the I/O is somebody
/// else's problem.
///
/// Same pure-planner / IO-applier split R859-F1 used for the apex
/// ([`plan_domain_passway`](crate::reconciler::domain::plan_domain_passway) vs
/// [`deploy_domain_passway`](crate::reconciler::domain::deploy_domain_passway)),
/// and the same one `yubaba`'s `scheduler::decide_transfer` uses. Nothing here
/// touches a network, a clock or a config file.
///
/// # The gating rule: fail-closed on withdrawal, fail-open on addition
///
/// Deliberately the same rule R859-F1 wrote for its apex prune
/// ([`DomainPasswayPlan::origins_complete`](crate::reconciler::domain::DomainPasswayPlan::origins_complete)),
/// and cited here so the two stay one rule rather than two coincidences.
/// Taking something *away* — an IP off the box currently serving it, an A
/// record out of the round-robin — on evidence we are not sure of is how a
/// leadership flap becomes a public outage. Adding can never make the apex
/// worse. So:
///
/// - A degraded quorum refuses [`Reassign`](IngressOwnerEffect::Reassign) and
///   [`Withdraw`](IngressOwnerEffect::Withdraw), which are both withdrawals
///   from somebody's point of view (a reassign takes the IP off the old owner).
///   This is `yubaba-failover.md` pre-check 1 — *"do not fail over out of a
///   degraded quorum — you will lose it entirely"* — enforced instead of read.
/// - Liveness may only ever **veto**, never approve. A `Reassign` proceeds on
///   [`Unconfirmed`](OwnerLiveness::Unconfirmed) because the `ingress_owner`
///   write is *itself* a consensus fact that the node came up and served
///   (`leader.rs`'s `on_became_leader` only writes it after the appliance
///   starts); demanding a second, independent confirm dwell would stall every
///   legitimate failover by one dwell and stall a freshly-elected leader — whose
///   tracker is empty — indefinitely. Only
///   [`ConfirmedDown`](OwnerLiveness::ConfirmedDown), positive contrary
///   evidence, refuses. A `Withdraw` is the mirror image: it *requires*
///   `ConfirmedDown`, because a withdrawal must rest on positive evidence.
///
/// # This planner never transfers leadership, and must not learn to
///
/// It *reacts* to an `ingress_owner` change and can never *cause* one. Making
/// the effector transfer leadership would make it a second consensus mechanism
/// racing the real one — the objection `yubaba`'s `failure_detector` module doc
/// already makes. `cloud.mesh_failover` (W271) stays the operator path, with
/// its `ask_user` confirmation and its rollback, and is untouched by this.
///
/// # TTL is deliberately not an input
///
/// The cross-provider path publishes through R859-F1's apex renderer, which
/// writes records at the `dns.record.upsert` default `ttl = 1` (Cloudflare
/// "auto"). Auto-TTL on a DNS-only record is already short enough for a
/// withdrawal to take effect on the cross-provider timescale, so there is no
/// manifest TTL field and this function has no TTL parameter. Recorded here so
/// the next reader does not re-open it.
pub fn plan_ingress_owner_effect(
    previous_owner: Option<&str>,
    current_owner: Option<&str>,
    current_owner_liveness: OwnerLiveness,
    quorum: &QuorumHealth,
    machines: &[MachineConfig],
) -> IngressOwnerEffect {
    let Some(owner) = current_owner else {
        // `ClearIngressOwner`. There is no "detach the IP" verb and Tier 1 has
        // no specified safe-unassigned state, so leaving the IP where it is —
        // on the last node known to have served — is the correct default. See
        // `on_ingress_owner_changed`'s doc, which records the same conclusion.
        return IngressOwnerEffect::NoOp {
            reason: match previous_owner {
                Some(prev) => format!(
                    "ingress owner cleared (was {prev}) — leaving the floating IP on the \
                     last-known-good node; there is no detach verb and no specified \
                     safe-unassigned state at Tier 1"
                ),
                None => "no ingress owner recorded".to_string(),
            },
        };
    };

    let machine = match resolve_ingress_owner(owner, machines) {
        Ok(m) => m,
        Err(e) => return IngressOwnerEffect::Refuse { reason: format!("{e:#}") },
    };

    let owner_changed = previous_owner != Some(owner);

    if owner_changed {
        let Some(ip_id) = machine.ingress_floating_ip.as_deref() else {
            // The common case, and a clean skip rather than an error: most
            // machines have no floating IP, and a fleet whose ingress moves by
            // DNS alone is a supported shape, not a misconfiguration.
            return IngressOwnerEffect::NoOp {
                reason: format!(
                    "ingress owner moved to {owner}, which declares no `ingress_floating_ip` — \
                     this machine has no floating-IP path"
                ),
            };
        };
        if current_owner_liveness == OwnerLiveness::ConfirmedDown {
            return IngressOwnerEffect::Refuse {
                reason: format!(
                    "ingress owner moved to {owner}, but liveness has confirmed it DOWN — \
                     refusing to point the public IP at a box we have positive evidence is dead"
                ),
            };
        }
        if let QuorumHealth::Degraded { reason } = quorum {
            return IngressOwnerEffect::Refuse {
                reason: format!(
                    "ingress owner moved to {owner} but the reassign is refused: {reason} \
                     (yubaba-failover.md pre-check 1). A reassign takes the IP off the old \
                     owner, so it is a withdrawal and fails closed."
                ),
            };
        }
        return IngressOwnerEffect::Reassign {
            machine: owner.to_string(),
            ip_id: ip_id.to_string(),
        };
    }

    // Owner unchanged. The only thing that can want an action now is the owner
    // itself dying — the cross-provider case, where no new owner has been
    // elected (or none can be) and the live apex is still pointing traffic at a
    // dead box.
    if current_owner_liveness == OwnerLiveness::ConfirmedDown {
        if let QuorumHealth::Degraded { reason } = quorum {
            return IngressOwnerEffect::Refuse {
                reason: format!(
                    "ingress owner {owner} is confirmed down, but the withdrawal is refused: \
                     {reason} (yubaba-failover.md pre-check 1)"
                ),
            };
        }
        return IngressOwnerEffect::Withdraw {
            machine: owner.to_string(),
            reason: format!("ingress owner {owner} is confirmed down by the lease channel"),
        };
    }

    IngressOwnerEffect::NoOp {
        reason: format!("ingress owner unchanged ({owner}) and not confirmed down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// A fake, network-free [`FloatingIpProvider`] — proves
    /// [`reconcile_assignment`]'s idempotency + zone-mismatch-reject logic
    /// in isolation from any vendor wire format (the per-provider mock-HTTP
    /// tests in `hetzner_floating_ip.rs` / `ovh_floating_ip.rs` /
    /// `vultr_floating_ip.rs` cover the wire-level shape).
    struct FakeProvider {
        zone: &'static str,
        attached_to: Mutex<Option<String>>,
        reassign_calls: AtomicU32,
    }

    #[async_trait]
    impl FloatingIpProvider for FakeProvider {
        fn id(&self) -> &'static str {
            "fake"
        }
        async fn resolve_target(&self, machine: &MachineConfig) -> Result<FloatingIpTarget> {
            Ok(FloatingIpTarget {
                attach_id: machine.name.clone(),
                zone: self.zone.to_string(),
            })
        }
        async fn current_assignment(&self, _ip_id: &str) -> Result<FloatingIpState> {
            Ok(FloatingIpState {
                zone: self.zone.to_string(),
                attached_to: self.attached_to.lock().unwrap().clone(),
            })
        }
        async fn reassign(&self, _ip_id: &str, target: &FloatingIpTarget) -> Result<()> {
            self.reassign_calls.fetch_add(1, Ordering::SeqCst);
            *self.attached_to.lock().unwrap() = Some(target.attach_id.clone());
            Ok(())
        }
    }

    fn machine(name: &str) -> MachineConfig {
        MachineConfig {
            name: name.into(),
            provider: "fake".into(),
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
            connect: None,
            allocatable: None,
            taints: vec![],
            sovereign_group: None,
            sovereign_role: None,
            ingress_floating_ip: None,
        }
    }

    #[tokio::test]
    async fn ownership_flip_drives_exactly_one_reassign_call() {
        let provider = FakeProvider {
            zone: "us-west",
            attached_to: Mutex::new(Some("old-node".into())),
            reassign_calls: AtomicU32::new(0),
        };
        let outcome = on_ingress_owner_changed(&provider, &machine("new-node"), "ip-1")
            .await
            .unwrap();
        assert!(outcome.reassigned);
        assert_eq!(outcome.attached_to, "new-node");
        assert_eq!(provider.reassign_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reapplying_the_same_owner_is_a_zero_call_noop() {
        let provider = FakeProvider {
            zone: "us-west",
            attached_to: Mutex::new(Some("new-node".into())),
            reassign_calls: AtomicU32::new(0),
        };
        let outcome = on_ingress_owner_changed(&provider, &machine("new-node"), "ip-1")
            .await
            .unwrap();
        assert!(!outcome.reassigned);
        assert_eq!(outcome.attached_to, "new-node");
        assert_eq!(
            provider.reassign_calls.load(Ordering::SeqCst),
            0,
            "idempotent re-apply must not call reassign"
        );
    }

    #[tokio::test]
    async fn never_assigned_ip_gets_a_first_assign_call() {
        let provider = FakeProvider {
            zone: "us-west",
            attached_to: Mutex::new(None),
            reassign_calls: AtomicU32::new(0),
        };
        let outcome = on_ingress_owner_changed(&provider, &machine("new-node"), "ip-1")
            .await
            .unwrap();
        assert!(outcome.reassigned);
        assert_eq!(provider.reassign_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cross_zone_target_is_rejected_before_any_reassign_call() {
        let provider = FakeProvider {
            zone: "eu-central",
            attached_to: Mutex::new(None),
            reassign_calls: AtomicU32::new(0),
        };
        let target = FloatingIpTarget {
            attach_id: "new-node".into(),
            zone: "us-west".into(),
        };
        let err = reconcile_assignment(&provider, "ip-1", &target)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("zone"),
            "expected a zone-mismatch message, got: {msg}"
        );
        assert_eq!(
            provider.reassign_calls.load(Ordering::SeqCst),
            0,
            "zone mismatch must never call reassign"
        );
    }

    // ── R859-F2: the registry ─────────────────────────────────────────────

    #[test]
    fn the_three_shipped_adapters_are_all_reachable_by_provider_id() {
        for id in ["hetzner", "ovh", "vultr"] {
            assert!(
                provider_has_floating_ip_adapter(id),
                "{id} ships a FloatingIpProvider impl but the registry cannot reach it"
            );
        }
        for id in ["digitalocean", "static", "local-docker", ""] {
            assert!(!provider_has_floating_ip_adapter(id), "{id}");
        }
    }

    /// The declaration error and the environment error are different failures
    /// wanting different fixes, so they must not collapse into one message.
    #[test]
    fn a_provider_with_no_adapter_is_refused_by_name_before_any_credential_lookup() {
        let mut m = machine("us-west-002");
        m.provider = "digitalocean".into();
        let err = match floating_ip_provider_for(&m) {
            Ok(_) => panic!("digitalocean has no floating-IP adapter but the registry built one"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("us-west-002"), "{msg}");
        assert!(msg.contains("digitalocean"), "{msg}");
        assert!(
            msg.contains("hetzner") && msg.contains("ovh") && msg.contains("vultr"),
            "the refusal should name what IS supported: {msg}"
        );
    }

    // ── R859-F2: plan_ingress_owner_effect ────────────────────────────────

    fn fleet() -> Vec<MachineConfig> {
        let mut west = machine("us-west-001");
        west.provider = "hetzner".into();
        west.ingress_floating_ip = Some("fip-42".into());
        let mut east = machine("us-east-001");
        east.provider = "hetzner".into();
        east.ingress_floating_ip = Some("fip-42".into());
        // Declared, but no floating-IP path — the common case.
        let mesh_only = machine("us-west-002");
        vec![west, east, mesh_only]
    }

    fn degraded() -> QuorumHealth {
        QuorumHealth::Degraded {
            reason: "quorum AT RISK: 2/3 voters available".into(),
        }
    }

    #[test]
    fn an_ownership_flip_onto_a_machine_with_a_floating_ip_reassigns_it() {
        let effect = plan_ingress_owner_effect(
            Some("us-west-001"),
            Some("us-east-001"),
            OwnerLiveness::ConfirmedUp,
            &QuorumHealth::Healthy,
            &fleet(),
        );
        assert_eq!(
            effect,
            IngressOwnerEffect::Reassign {
                machine: "us-east-001".into(),
                ip_id: "fip-42".into(),
            }
        );
        assert!(effect.is_action());
    }

    /// Liveness may only ever veto. A freshly-elected leader's tracker is empty,
    /// so requiring a positive confirm would stall exactly the failover this
    /// exists to perform — and the `ingress_owner` write is itself evidence the
    /// node came up and served.
    #[test]
    fn an_unconfirmed_new_owner_still_reassigns_because_liveness_may_only_veto() {
        assert!(matches!(
            plan_ingress_owner_effect(
                Some("us-west-001"),
                Some("us-east-001"),
                OwnerLiveness::Unconfirmed,
                &QuorumHealth::Healthy,
                &fleet(),
            ),
            IngressOwnerEffect::Reassign { .. }
        ));
    }

    #[test]
    fn a_new_owner_confirmed_down_is_refused_rather_than_pointed_at() {
        let effect = plan_ingress_owner_effect(
            Some("us-west-001"),
            Some("us-east-001"),
            OwnerLiveness::ConfirmedDown,
            &QuorumHealth::Healthy,
            &fleet(),
        );
        assert!(matches!(effect, IngressOwnerEffect::Refuse { .. }), "{effect:?}");
        assert!(effect.reason().contains("DOWN"), "{}", effect.reason());
    }

    /// `yubaba-failover.md` pre-check 1, enforced: a reassign takes the IP off
    /// the old owner, so it is a withdrawal and fails closed.
    #[test]
    fn a_degraded_quorum_refuses_the_reassign_and_carries_the_verdicts_reason() {
        let effect = plan_ingress_owner_effect(
            Some("us-west-001"),
            Some("us-east-001"),
            OwnerLiveness::ConfirmedUp,
            &degraded(),
            &fleet(),
        );
        assert!(matches!(effect, IngressOwnerEffect::Refuse { .. }), "{effect:?}");
        assert!(
            effect.reason().contains("2/3 voters available"),
            "the refusal must carry the quorum verdict's own reason, got: {}",
            effect.reason()
        );
    }

    /// The other half of decision 3, and the half that is easy to get wrong:
    /// refusing on a degraded quorum applies to withdrawals, never to
    /// additions. Nothing here gates an upsert — see
    /// `diff_apex_records`, whose `upsert` is untouched by every gate.
    #[test]
    fn a_machine_with_no_floating_ip_is_a_clean_skip_not_an_error() {
        let effect = plan_ingress_owner_effect(
            Some("us-west-001"),
            Some("us-west-002"),
            OwnerLiveness::ConfirmedUp,
            &QuorumHealth::Healthy,
            &fleet(),
        );
        assert!(matches!(effect, IngressOwnerEffect::NoOp { .. }), "{effect:?}");
        assert!(!effect.is_action());
        assert!(
            effect.reason().contains("no floating-IP path"),
            "{}",
            effect.reason()
        );
    }

    #[test]
    fn a_steady_healthy_owner_does_nothing() {
        let effect = plan_ingress_owner_effect(
            Some("us-east-001"),
            Some("us-east-001"),
            OwnerLiveness::ConfirmedUp,
            &QuorumHealth::Healthy,
            &fleet(),
        );
        assert!(matches!(effect, IngressOwnerEffect::NoOp { .. }), "{effect:?}");
    }

    /// The cross-provider path: no new owner has been elected, and the one we
    /// have is confirmed dead. A withdrawal REQUIRES the positive
    /// `ConfirmedDown`, which is the mirror of the reassign's veto-only rule.
    #[test]
    fn a_steady_owner_confirmed_down_is_withdrawn_from_the_apex() {
        let effect = plan_ingress_owner_effect(
            Some("us-east-001"),
            Some("us-east-001"),
            OwnerLiveness::ConfirmedDown,
            &QuorumHealth::Healthy,
            &fleet(),
        );
        assert_eq!(
            effect,
            IngressOwnerEffect::Withdraw {
                machine: "us-east-001".into(),
                reason: "ingress owner us-east-001 is confirmed down by the lease channel".into(),
            }
        );
    }

    #[test]
    fn a_degraded_quorum_refuses_the_withdrawal_too() {
        let effect = plan_ingress_owner_effect(
            Some("us-east-001"),
            Some("us-east-001"),
            OwnerLiveness::ConfirmedDown,
            &degraded(),
            &fleet(),
        );
        assert!(matches!(effect, IngressOwnerEffect::Refuse { .. }), "{effect:?}");
        assert!(effect.reason().contains("2/3 voters available"), "{}", effect.reason());
    }

    /// The mismatch R841 saw live: `ingress_owner` carries `/etc/hostname`,
    /// which is not always the machine name. Guessing here would reassign a
    /// live public IP onto the wrong box, so an unresolvable owner refuses and
    /// names both sides.
    #[test]
    fn an_ingress_owner_that_names_no_declared_machine_refuses_loudly() {
        let effect = plan_ingress_owner_effect(
            Some("us-west-001"),
            Some("vps-4c1efa56"),
            OwnerLiveness::ConfirmedUp,
            &QuorumHealth::Healthy,
            &fleet(),
        );
        assert!(matches!(effect, IngressOwnerEffect::Refuse { .. }), "{effect:?}");
        let reason = effect.reason();
        assert!(reason.contains("vps-4c1efa56"), "{reason}");
        assert!(
            reason.contains("us-west-001") && reason.contains("us-east-001"),
            "the refusal must name the declared machines it compared against: {reason}"
        );
        assert!(
            reason.contains("hostname"),
            "and must explain WHY the two spaces differ: {reason}"
        );
    }

    /// `ClearIngressOwner`. There is no detach verb and Tier 1 specifies no safe
    /// unassigned state, so the IP stays on the last node known to have served —
    /// the same conclusion `on_ingress_owner_changed`'s doc reaches.
    #[test]
    fn clearing_the_ingress_owner_leaves_the_ip_where_it_is() {
        let effect = plan_ingress_owner_effect(
            Some("us-east-001"),
            None,
            OwnerLiveness::ConfirmedDown,
            &QuorumHealth::Healthy,
            &fleet(),
        );
        assert!(matches!(effect, IngressOwnerEffect::NoOp { .. }), "{effect:?}");
        assert!(
            effect.reason().contains("last-known-good"),
            "{}",
            effect.reason()
        );
    }

    #[test]
    fn no_ingress_owner_at_all_is_a_no_op() {
        assert!(matches!(
            plan_ingress_owner_effect(
                None,
                None,
                OwnerLiveness::Unconfirmed,
                &QuorumHealth::Healthy,
                &fleet(),
            ),
            IngressOwnerEffect::NoOp { .. }
        ));
    }

    /// First observation after this process started: `previous_owner` is `None`
    /// but an owner is recorded. That is a change from this planner's point of
    /// view and must converge the IP rather than wait for a flip that already
    /// happened — the planner carries no state across ticks, so "unchanged" can
    /// only ever mean "unchanged since the last tick I saw".
    #[test]
    fn a_first_observation_of_an_existing_owner_converges_the_ip() {
        assert_eq!(
            plan_ingress_owner_effect(
                None,
                Some("us-east-001"),
                OwnerLiveness::ConfirmedUp,
                &QuorumHealth::Healthy,
                &fleet(),
            ),
            IngressOwnerEffect::Reassign {
                machine: "us-east-001".into(),
                ip_id: "fip-42".into(),
            },
            "reconcile_assignment is idempotent, so a redundant converge costs zero \
             provider calls — but skipping it would leave a stale IP unfixed forever"
        );
    }
}
