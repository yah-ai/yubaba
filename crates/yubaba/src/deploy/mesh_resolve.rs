//! Deploy-time mesh-address resolution for yubaba workloads (R090-F6).
//!
//! Bridges [`workload_spec::EnvValue::FromMesh`] references to literal env
//! values rendered from the cluster's currently-deployed mesh state. Two
//! pieces:
//!
//! 1. [`MeshState`] — read-only view of "which mesh idents are deployed and
//!    which ports they expose", abstracted so the production impl
//!    ([`ServiceRecordMeshState`], reading the node's service-record registry)
//!    and the in-memory test fake share one seam.
//! 2. [`StateMeshResolver`] — adapter implementing
//!    [`workload_spec::validate::MeshResolver`] from [`MeshState`]; resolves
//!    `Url` / `Host` / `Port` per the arch doc.
//!
//! Plus [`await_dependencies`], which polls [`MeshState`] every 250ms (or a
//! caller-supplied cadence) until every one of the spec's
//! [`gated_requirements`] is satisfied — Ready, and on this node when the
//! requirement says `local` (W338) — or fails once the deadline elapses. It
//! reads [`workload_spec::WorkloadSpec::effective_requirements`], so `requires`
//! and the legacy `depends_on` are gated alike.
//!
//! **Stage placement:** F4 stage 3 (mesh peering) → F6 (this module) →
//! containerd start. `EnvValue::FromMesh` stays a reference at the spec
//! layer; only becomes a literal when yubaba assembles the containerd spec
//! after this module renders it.
//!
//! @yah:ticket(R860-T2, "Deploy gate: locality-aware, Ready-gated requirement satisfaction in await_dependencies")
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:at(2026-09-05T18:29:08Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R860)
//! @yah:next("Gate on Ready, not on presence (W338 §Ordering and readiness). `MeshState::lookup` returning Some means \\\"appeared\\\"; a workload replaying a WAL binds its port and lies. procctl (oss/kamaji/crates/procctl, W315) already carries pending|starting|running|draining|exited|failed verbatim. Requirements must wait for `running`, and for a Job-archetype provider must wait for `exited` success — that is what subsumes the init-container shape without adding one.")
//! @yah:verify("cargo test -p yubaba --lib deploy::mesh_resolve")
//! @yah:gotcha("Do not touch oss/yubaba/crates/yubaba/src/{headscale_appliance,appliance_ownership,headscale_state,litestream,leader}.rs — @Ashguard:eclipse (session:83093d9d) holds them live on R858. This ticket is the generic gate only; R858 wires headscale onto it.")
//! @arch:see(.yah/docs/working/W338-workload-dependencies-and-appliance-composition.md)
//! @yah:depends_on(R860-T1)
//! @yah:next("SEQUENCING CORRECTION (2026-09-04): depends on R860-B3, not just T1. await_dependencies has zero production callers, so a locality gate built on it today would be dead code widening dead code. B3 wires the rail; this ticket adds the locality + Ready axes on top.")
//! @yah:next("READINESS SOURCE — do NOT reach for procctl from here. Verified: oss/yubaba/crates/cloud/src/proc_control.rs is read only from reconciler/mod.rs:465-544 and reconciler/local_process.rs (the dev/local-process tier); the cloud deploy path has no procctl consumer at all. The reachable Ready signal from deploy/ is the ServiceRecord ready flag (`GET /service-records?ready=true`). LOCALITY TEST is an address comparison, not a node-id one: ServiceRecord carries `mesh_ip: Ipv4Addr` invariantly equal to the answering node's own address (service_records.rs:363-377, R844-B11), and the running node knows itself as ServerState::node_mesh_ip (yubaba/src/lib.rs:1080, accessor :1296). So `local` == `record.mesh_ip == state.node_mesh_ip()`. There is no node identifier on either side of that seam.")
//! @yah:handoff("LANDED. The deploy gate now enforces W338's locality table and its Ready rule instead of a plain presence check. Three seams: (1) `MeshAddress` gained `provider_mesh_ip: Option<Ipv4Addr>` (which NODE the provider runs on) and `ready: bool`; (2) the `MeshState` trait gained a required `node_mesh_ip() -> Option<Ipv4Addr>` — the observer's own address, the other half of the comparison, since there is no node identifier anywhere on this seam; (3) `ServiceRecordMeshState::new` now takes that address and `deploy_workload_spec` passes `s.node_mesh_ip()` (yubaba/src/lib.rs, the R860-B3 gate block). Satisfaction moved out of `await_dependencies`' loop body into `requirement_satisfied(req, state)`: presence, then Ready, then — for `Locality::Local` only — `provider_mesh_ip == node_mesh_ip()`. `anywhere` is untouched (any Ready provider), `prefer-local` still never reaches the gate.")
//! @yah:handoff("DECISIONS THE BRIEF DID NOT COVER, all made rather than asked. (1) `gated_idents` was RENAMED to `gated_requirements` and now returns `Vec<Requirement>`, not `Vec<MeshIdent>`. An ident alone cannot answer the locality question, so any caller handed only idents was structurally unable to enforce the table — that type is why `local` meant nothing for a relay. No callers outside mesh_resolve.rs (grepped: `MeshAddress|gated_idents|InMemoryMeshState|impl MeshState` returns nothing elsewhere in oss/ crates/ app/ xtask/). (2) FAILURE REASONS TRAVEL AS `MeshError::Lookup` FREE TEXT, not a new enum variant. `MeshError` lives in workload-spec (oss/yah-base), a shared crate this ticket was not sent to touch, and adding a variant risks exhaustive-match breakage in peers' code. `Absent` still maps to `MeshError::NotDeployed` so the pre-existing tests and the operator-facing wording for the common case are unchanged; NotReady and NotLocal get `Lookup` with a sentence naming the ident, the locality and the actual node. All three render into the same 424 body the handler already formats. (3) `ServiceRecordMeshState::lookup` STAYS PRESENCE-BASED — readiness rides out as `MeshAddress::ready` and is applied by the gate. Filtering at the lookup would also blind `StateMeshResolver`, and a `FromMesh` env reference to an ungated provider (a `prefer-local` one) must still render. B3's handoff suggested filtering inside `lookup`; that would have been a silent env-resolution regression.")
//! @yah:handoff("LOCALITY FAILS CLOSED, and this is the decision to re-read before changing it. If `node_mesh_ip()` is `None` (yubaba bound to loopback / 0.0.0.0 / a non-IP host — see `parse_node_mesh_ip`, lib.rs), or the state source cannot say which node a provider is on, a `local` requirement is REFUSED rather than degraded to `anywhere`. Pinned by `a_local_requirement_is_unsatisfiable_when_this_node_has_no_mesh_address`, which asserts the refusal says \"not on any mesh plane\" and not \"not deployed\" — the two are different operator problems. Rationale: the motivating edge is a sqlite replicator that must open the same file on the same filesystem, so admitting a remote provider is data corruption, not a scheduling inefficiency. An unsatisfiable requirement fails one deploy loudly; a silently-widened one succeeds and is wrong. CONSEQUENCE FOR OPERATORS: a node that has no `--bind` mesh address cannot run ANY workload declaring `locality = \"local\"` + `supply = \"wait\"`. That is intended, and is why `supply = \"self\"` (which never reaches the gate) is the shape W338's sidecar case actually uses.")
//! @yah:handoff("DISCOVERED WORK DONE IN THIS PASS, beyond the ticket title. (1) R860-T6's `waits_on` test helper (yubaba/src/lib.rs, near the `self_supplied` helper) declared `locality: Locality::Local`. That was INERT when written — the gate presence-checked every locality — and became load-bearing the instant locality was enforced, turning two of T6's green tests red (`a_wait_provider_is_never_deployed_by_its_requirer` and `destroy_cascades_into_self_providers_and_leaves_wait_providers_standing`, both 424 where they expected 201), because those fixtures build a `ServerState` with no bind address so `node_mesh_ip()` is `None`. Neither test is about locality — they are about `supply` — so the helper now says `Locality::Anywhere`, which is the locality of \"belongs to whoever declared it\", with a doc comment recording why and pointing at the tests that DO cover `local`. This is the failure mode the ticket exists for showing up in the relay's own fixtures, not a regression I introduced. (2) The two stale claims at the old mesh_resolve.rs:253-265 are corrected, as are the module header's \"until every entry in `spec.depends_on` appears\" and `ServiceRecordMeshState`'s \"Presence, not readiness\" paragraph — that comment was what told the leader what was missing, and leaving it is how the next reader repeats the bug. (3) W338's \"What already exists\" table row for `depends_on` now says satisfaction is Ready + locality-aware as of R860-T2; the healthcheck-sum-deadline caveat B3 added is still true and was kept.")
//! @yah:verify("BASELINE, measured before any edit: `cargo test -p yubaba --lib` from oss/yubaba = 697 passed / 0 failed, exit 0. AFTER: 708 passed / 0 failed, exit 0. +11 is exactly the eleven new tests; no pre-existing test lost or was deleted. `cargo check -p yubaba --all-targets` = exit 0, zero errors (the two `unused import` warnings are pre-existing in crates/cloud/src/reconciler/mesofact_static.rs, not mine). An intermediate run showed 706/2 — those two were R860-T6's `waits_on` fixtures, fixed as described in the discovered-work note, not suppressed.")
//! @yah:verify("ELEVEN NEW TESTS, each asserting on the GATE's verdict, never on the helper. Unit, in deploy::mesh_resolve (all confirmed registered via `cargo test -p yubaba --lib -- --list`): a_local_requirement_is_not_satisfied_by_a_ready_provider_on_another_node (the headline case — also asserts the refusal names the ident, the locality and the node the provider is actually on), a_local_requirement_is_satisfied_by_a_provider_on_this_node, a_local_requirement_is_unsatisfiable_when_this_node_has_no_mesh_address, an_anywhere_requirement_is_satisfied_by_a_provider_on_another_node, a_present_but_not_ready_provider_does_not_satisfy_a_requirement, a_not_ready_provider_blocks_a_legacy_depends_on_entry_too, a_prefer_local_requirement_never_blocks_even_with_no_provider_at_all, a_requirement_is_released_once_its_provider_turns_ready. END-TO-END through the real router in lib.rs, because a unit test cannot tell a correctly-threaded node address from a hardcoded one: a_local_requirement_is_refused_when_its_only_provider_is_on_another_node (424 AND the recording backend saw zero deploys), a_local_requirement_is_satisfied_by_a_provider_on_this_node (same spec, same registry, one address changed -> 201; flip the wiring to a hardcoded None and this one fails while its twin still passes, which is what makes the pair prove the threading), a_present_but_not_ready_record_does_not_satisfy_the_gate (a RETRACTED record — asserts the record is still `get`-able first, so the test is about readiness and not about absence).")
//! @yah:verify("NOT RUN, stated plainly: nothing was executed against a live fleet node, and no oss/yubaba integration-test suite was run (only compiled, via --all-targets). No workspace-wide `cargo check` from the repo root — `MeshAddress`/`MeshState` are constructed and implemented in exactly one file (grep for `MeshAddress|gated_idents|InMemoryMeshState|impl MeshState` across oss/ crates/ app/ xtask/ returns nothing outside deploy/mesh_resolve.rs), and `ServiceRecordMeshState::new`'s only caller is deploy_workload_spec, so --all-targets inside oss/yubaba is the run that covers the blast radius.")
//! @yah:gotcha("THE `local` GATE ONLY EVER ANSWERS ABOUT THIS NODE'S REGISTRY, which is the right answer for `local` and would be the wrong one for anything wider. `ServiceRecords` holds only records this node published, so \"no provider here\" and \"a provider on another node\" are indistinguishable by ABSENCE — the locality test works because a record that IS present carries its node's address (R844-B11), not because the registry is fleet-wide. That is exactly why `prefer-local` is still excluded from the gate rather than implemented as \"local, else anywhere\": implementing the fallback needs a fleet-wide read this seam does not have. Do not \"fix\" prefer-local here without one.")
//! @yah:handoff("SHARED-TREE STATE, uncommitted, nothing was committed. Three files carry my hunks — verify by CONTENT, not by git status: oss/yubaba/crates/yubaba/src/deploy/mesh_resolve.rs (grep `provider_mesh_ip`, `gated_requirements`, `requirement_satisfied`, `Unsatisfied`), oss/yubaba/crates/yubaba/src/lib.rs (grep `state_with_recording_runtime_on_node` and `s.node_mesh_ip()` in the gate block), .yah/docs/working/W338-workload-dependencies-and-appliance-composition.md (the depends_on table row). Tree anchor for this dispatch was 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — quote that SHA, never HEAD, in any revert instruction. NO COLLISION OBSERVED: `camp.roster` at edit time showed @Ashguard:eclipse (session:83093d9d) live on R858 but parked in a `board.handoff` awaiting an operator go/no-go, and none of the five R858-held files (headscale_appliance, appliance_ownership, headscale_state, litestream, leader) was touched. My lib.rs edits are confined to the `deploy_workload_spec` gate block and the test module; the known non-mine hunk at `pub mod cert_materialize;` (~:402) was left alone. Any commit of this work must be pathspec-scoped.")
//! @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:handoff("LEADER RE-VERIFIED (session:69b18855, independent of the courier's self-report). `cargo test -p yubaba --lib` from oss/yubaba: 708 passed / 0 failed, exit 0, against the 697/0 baseline R860-T6 established — +11 = exactly its new tests. Confirmed by content in deploy/mesh_resolve.rs: `MeshAddress.provider_mesh_ip: Option&lt;Ipv4Addr&gt;` :104 and `MeshAddress.ready: bool` :114 (filled from `ServiceRecord::is_ready`, the same flag behind `GET /service-records?ready=true`), plus `MeshState::node_mesh_ip()` :144 threaded from `ServerState::node_mesh_ip` through `ServiceRecordMeshState` :261-274. The courier reported an intermediate 706/2 and fixed the cause rather than the symptom — R860-T6's `waits_on` fixture was declaring an inert `Locality::Local` that only became load-bearing once this ticket made locality real.")
//! @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("cargo test -p yubaba --lib (from oss/yubaba): 708 passed / 0 failed, exit 0, vs a 697/0 baseline. cargo check -p yubaba --all-targets exit 0. Exit codes echoed explicitly throughout.")
//! @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("RE-VERIFIED AT HEAD 00ee20d1 (session:aa5e882d, 2026-09-05). Confirmed by content in oss/yubaba/crates/yubaba/src/deploy/mesh_resolve.rs: `pub provider_mesh_ip: Option&lt;Ipv4Addr&gt;` :109 and the `node_mesh_ip` doc-comment contract at :146 (the fail-closed locality comparison). `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 731 passed / 0 failed, exit 0.")

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::time::Instant;
use workload_spec::validate::{MeshError, MeshResolver};
use workload_spec::{Locality, MeshIdent, MeshLookup, Requirement, Supply, WorkloadSpec};

/// Snapshot of a deployed workload's mesh exposure as visible to the
/// resolver. Returned by [`MeshState::lookup`].
///
/// `dependency_wait_deadline` is the time yubaba should be willing to wait
/// for *this workload* to come up before failing dependents — i.e.
/// `failure_threshold × interval + initial_delay` from its `Healthcheck`,
/// or a sensible default for workloads without one. Used by
/// [`compute_dependency_deadline`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAddress {
    pub ident: MeshIdent,
    /// The address a dependent should actually dial, when the state source
    /// knows one (R860-B3).
    ///
    /// `None` means "use the ident" — the documented
    /// [`workload_spec::validate::MeshResolver`] rule, and what the in-memory
    /// state has always done. [`ServiceRecordMeshState`] fills it with the
    /// record's `mesh_ip`, because that is the only address anything on this
    /// fleet is actually configured to reach: nothing publishes mesh idents
    /// into DNS, so a dependent handed `http://<ident>:<port>` cannot resolve
    /// it. `MeshLookup::Host` deliberately still answers the ident — it is
    /// documented as "the bare DNS-ish identifier as authored" and a caller
    /// asking for the *name* is not asking for an address.
    pub dial_host: Option<String>,
    /// The peer's listeners as `name -> port` (R844-B22).
    ///
    /// Was a `Vec<u16>`, which is why every lookup here resolved positionally:
    /// a bare list cannot answer "which of these is the API port", so the code
    /// answered "the first" and the trait doc wrote that down as a rule. This
    /// is the same `BTreeMap<String, u16>` that `kamaji::WorkloadState::ports`
    /// and `ServiceRecord::resolved_ports` carry, so a name survives from the
    /// manifest all the way to a dependent's environment.
    pub ports: BTreeMap<String, u16>,
    /// The mesh address of the node this provider is running on, when the
    /// state source knows one (R860-T2).
    ///
    /// Deliberately typed and separate from [`Self::dial_host`] even though
    /// [`ServiceRecordMeshState`] fills both from the same `record.mesh_ip`:
    /// `dial_host` answers "what does a dependent connect to", this answers
    /// "which node is it on", and only the second one can decide a
    /// [`Locality::Local`] requirement. Comparing a stringly-typed dial host
    /// against an `Ipv4Addr` would make the load-bearing locality test depend
    /// on formatting.
    ///
    /// `None` means the state source cannot say. A `local` requirement is then
    /// **unsatisfiable** rather than degraded to `anywhere` — see
    /// [`await_dependencies`].
    pub provider_mesh_ip: Option<Ipv4Addr>,
    /// Whether the provider is Ready, not merely present (R860-T2, W338
    /// §"Ordering and readiness").
    ///
    /// [`ServiceRecordMeshState`] fills this from [`ServiceRecord::is_ready`],
    /// the same flag behind `GET /service-records?ready=true`. Presence is not
    /// readiness: a restore still replaying a WAL has a record and a bound
    /// port, and the port lies.
    ///
    /// [`ServiceRecord::is_ready`]: crate::service_records::ServiceRecord::is_ready
    pub ready: bool,
    pub dependency_wait_deadline: Option<Duration>,
}

/// Read-only view of the cluster's deployed mesh state.
///
/// The production impl is [`ServiceRecordMeshState`] (the node's service-record
/// registry, which is also what `GET /service-records` serves); tests use
/// [`InMemoryMeshState`]. [`StateMeshResolver`] adapts any `MeshState` into a
/// [`MeshResolver`].
pub trait MeshState: Send + Sync {
    /// Returns the deployed address for `ident`, or `None` if it's not yet on
    /// the mesh. Implementations should be cheap — [`await_dependencies`]
    /// calls this on every poll tick.
    ///
    /// **Presence, not readiness.** This answers for any record the source
    /// holds; readiness rides on [`MeshAddress::ready`] and is applied by
    /// [`await_dependencies`], not here. Filtering it out at the lookup would
    /// also blind [`StateMeshResolver`], and a `FromMesh` env reference to an
    /// ungated provider (a `prefer-local` one, say) must still render.
    fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress>;

    /// This node's **own** mesh address, or `None` when it has none — the
    /// other half of the [`Locality::Local`] test (R860-T2).
    ///
    /// There is no node identifier on either side of this seam, so locality is
    /// an address comparison: a requirement is local iff the provider's
    /// [`MeshAddress::provider_mesh_ip`] equals this. `None` here (yubaba bound
    /// to loopback, `0.0.0.0`, or a non-IP host) makes every `local`
    /// requirement unsatisfiable rather than silently `anywhere`.
    fn node_mesh_ip(&self) -> Option<Ipv4Addr>;
}

/// Adapter that implements [`MeshResolver`] using a [`MeshState`] for lookups.
///
/// The resolution rules — including **which** port a `Url` / `Port` lookup
/// selects when the peer has several — live in
/// [`workload_spec::validate::select_mesh_port`], not here. This impl is the
/// adapter and nothing more: re-deriving the rule locally is exactly how this
/// file came to promise "the first entry" while the rest of the workspace had
/// moved to names (R844-B22).
pub struct StateMeshResolver<'a> {
    state: &'a dyn MeshState,
}

impl<'a> StateMeshResolver<'a> {
    pub fn new(state: &'a dyn MeshState) -> Self {
        Self { state }
    }
}

impl<'a> MeshResolver for StateMeshResolver<'a> {
    fn resolve(&self, ident: &MeshIdent, kind: MeshLookup) -> Result<String, MeshError> {
        let addr = self
            .state
            .lookup(ident)
            .ok_or_else(|| MeshError::NotDeployed {
                ident: ident.0.clone(),
            })?;
        if !kind.needs_port() {
            return Ok(addr.ident.0.clone());
        }
        let port = workload_spec::validate::select_mesh_port(&ident.0, &addr.ports, &kind)?;
        match kind {
            MeshLookup::Host => unreachable!("Host needs no port"),
            MeshLookup::Port | MeshLookup::PortNamed { .. } => Ok(port.to_string()),
            MeshLookup::Url | MeshLookup::UrlNamed { .. } => {
                let host = addr.dial_host.as_deref().unwrap_or(&addr.ident.0);
                Ok(format!("http://{host}:{port}"))
            }
        }
    }
}

// ── In-memory state used by tests and by yubaba's pre-raft single-node mode ──

/// Simple `HashMap`-backed [`MeshState`] for tests.
///
/// The deploy path uses [`ServiceRecordMeshState`]; this exists so a test can
/// state a mesh world directly instead of standing up a registry.
#[derive(Debug, Default, Clone)]
pub struct InMemoryMeshState {
    by_ident: HashMap<String, MeshAddress>,
    node_mesh_ip: Option<Ipv4Addr>,
}

impl InMemoryMeshState {
    pub fn new() -> Self {
        Self::default()
    }

    /// State the address this fake node knows itself by, so a
    /// [`Locality::Local`] requirement has something to compare against.
    /// Defaults to `None`, which is "this node has no mesh plane" and makes
    /// every `local` requirement unsatisfiable.
    pub fn with_node_mesh_ip(mut self, ip: Ipv4Addr) -> Self {
        self.node_mesh_ip = Some(ip);
        self
    }

    /// Register or replace an address for `ident`.
    pub fn insert(&mut self, addr: MeshAddress) {
        self.by_ident.insert(addr.ident.0.clone(), addr);
    }

    /// Remove an ident — used in tests that simulate a workload coming up
    /// after the dependent has started waiting.
    pub fn remove(&mut self, ident: &MeshIdent) {
        self.by_ident.remove(&ident.0);
    }
}

impl MeshState for InMemoryMeshState {
    fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress> {
        self.by_ident.get(&ident.0).cloned()
    }

    fn node_mesh_ip(&self) -> Option<Ipv4Addr> {
        self.node_mesh_ip
    }
}

// ── Production state: the node's service-record registry ─────────────────────

/// The production [`MeshState`] — reads [`crate::service_records::ServiceRecords`],
/// the registry `GET /service-records` already serves (R860-B3).
///
/// This is what makes `depends_on` and `EnvValue::FromMesh` mean anything on a
/// real node: before this existed the only `MeshState` implementors in the
/// workspace were [`InMemoryMeshState`] and a test double, so both halves of
/// this module were dead code and every documented guarantee about dependency
/// ordering was unenforced.
///
/// **Lookup is presence; satisfaction is not.** [`ServiceRecords::get`] answers
/// for any record the registry holds, including `NotReady`, `Retracted` and
/// rehydrated-from-ledger ones, and this impl deliberately keeps that — the
/// resolver half of the module needs to render a `FromMesh` reference to an
/// ungated provider. The readiness and locality facts a requirement is judged
/// on ride out on [`MeshAddress::ready`] / [`MeshAddress::provider_mesh_ip`],
/// where [`await_dependencies`] applies them (R860-T2).
///
/// `dependency_wait_deadline` is always `None`: a service record carries no
/// healthcheck, so [`compute_dependency_deadline`] falls back to the caller's
/// per-dep default for every dependency. Wiring real per-dep healthcheck
/// deadlines needs a spec-level source the registry does not have.
pub struct ServiceRecordMeshState<'a> {
    records: &'a crate::service_records::ServiceRecords,
    node_mesh_ip: Option<Ipv4Addr>,
}

impl<'a> ServiceRecordMeshState<'a> {
    /// `node_mesh_ip` is the running node's own mesh address
    /// (`ServerState::node_mesh_ip`) — the only thing a record's `mesh_ip` can
    /// be compared against to decide [`Locality::Local`].
    pub fn new(
        records: &'a crate::service_records::ServiceRecords,
        node_mesh_ip: Option<Ipv4Addr>,
    ) -> Self {
        Self {
            records,
            node_mesh_ip,
        }
    }
}

impl MeshState for ServiceRecordMeshState<'_> {
    fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress> {
        let record = self.records.get(ident)?;
        Some(MeshAddress {
            ident: record.ident.clone(),
            // R844-B11: a record's `mesh_ip` is always the answering node's own
            // mesh address, which is exactly the address passway dials.
            dial_host: Some(record.mesh_ip.to_string()),
            // ...and, by that same invariant, is the address of the node the
            // provider runs on. That is what makes the locality test possible
            // without a node identifier anywhere on this seam.
            provider_mesh_ip: Some(record.mesh_ip),
            ready: record.is_ready(),
            // Resolved (measured) ports when the supervisor reported any,
            // declared ports otherwise — see `ServiceRecord::dialable_ports`.
            ports: record.dialable_ports().clone(),
            dependency_wait_deadline: None,
        })
    }

    fn node_mesh_ip(&self) -> Option<Ipv4Addr> {
        self.node_mesh_ip
    }
}

// ── Dependency wait ──────────────────────────────────────────────────────────

/// Default poll cadence used when a caller doesn't override it.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long the deploy handler waits for ONE dependency whose own wait
/// deadline is unknown (R860-B3).
///
/// Every dependency is currently in that bucket — [`ServiceRecordMeshState`]
/// reports no `dependency_wait_deadline` because a service record carries no
/// healthcheck — so in practice the deploy gate's budget is
/// `depends_on.len() * this`. Chosen to be long enough for a co-deployed peer
/// to pull an image and bind, and short enough that a genuinely-absent
/// dependency fails the deploy with an actionable error instead of hanging the
/// HTTP request until the client gives up.
pub const DEFAULT_DEPENDENCY_WAIT_PER_DEP: Duration = Duration::from_secs(30);

/// The idents this gate actually waits on — R860-T6 / W338.
///
/// Read off [`WorkloadSpec::effective_requirements`], never off `depends_on`
/// alone: that accessor's own contract is that reading either field directly
/// "silently drops half the requirements of any spec that uses both", and until
/// this function existed both gate entry points did exactly that, so a
/// `requires`-declared dependency was gated on nothing. A spec that uses only
/// `depends_on` is unaffected — every entry folds in as `anywhere` + `wait`,
/// which both filters below admit.
///
/// Two requirement classes are deliberately **excluded**:
///
/// - [`Supply::SelfProvision`] — the requirer stands its provider up itself,
///   synchronously, before this gate runs (`deploy_workload_spec`), so the
///   ordering is already established by construction and there is nothing left
///   to wait for. Waiting anyway would be worse than redundant: a provider that
///   exposes no mesh ports publishes **no service record at all** (the deploy
///   handler retracts instead of upserting), so a Job-archetype restore step —
///   W338's motivating `local` + `self` case — would time out the very requirer
///   it had just been stood up for.
/// - [`Locality::PreferLocal`] — "never blocks placement" is that value's
///   defining property in W338's locality table. This node's registry holds only
///   this node's records, so absence here cannot distinguish "no provider
///   anywhere" from "a provider on another node", and blocking on it would
///   refuse exactly the deploys `prefer-local` exists to allow.
///
/// [`Locality::Local`] and [`Locality::Anywhere`] both survive this filter, but
/// they are **not** judged alike once through it: `anywhere` is satisfied by any
/// Ready provider, `local` only by one on this node. That distinction is
/// [`requirement_satisfied`], and both are gated on Ready rather than on
/// presence. This function only decides *which* requirements block a deploy.
///
/// Returns whole [`Requirement`]s rather than bare idents (it used to be
/// `gated_idents`): the ident alone cannot answer the locality question, so a
/// caller handed only idents was structurally unable to enforce W338's table —
/// which is exactly how `local` came to mean nothing for a relay.
pub fn gated_requirements(spec: &WorkloadSpec) -> Vec<Requirement> {
    spec.effective_requirements()
        .into_iter()
        .filter(|req| req.supply == Supply::Wait && req.locality != Locality::PreferLocal)
        .collect()
}

/// Why one gated requirement is not satisfied yet — kept apart from a bare
/// `false` so the deploy's 424 body says *which* of the three W338 conditions
/// failed. "Not deployed" and "deployed on the wrong node" are different
/// operator problems with different fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unsatisfied {
    /// No provider for this ident is known to the state source at all.
    Absent,
    /// A provider exists but is not Ready.
    NotReady,
    /// A Ready provider exists but is not on this node, and the requirement is
    /// [`Locality::Local`].
    NotLocal {
        provider: Option<Ipv4Addr>,
        this_node: Option<Ipv4Addr>,
    },
}

impl Unsatisfied {
    fn into_error(self, ident: &MeshIdent) -> MeshError {
        match self {
            Unsatisfied::Absent => MeshError::NotDeployed {
                ident: ident.0.clone(),
            },
            // `MeshError` has no variant for "present but unsatisfactory" and
            // adding one would mean changing a shared crate (workload-spec)
            // this ticket was not sent to touch, so the reason travels as
            // `Lookup`'s free text. It reaches the operator either way — the
            // deploy handler renders `dependency wait failed: {e}` into the 424.
            Unsatisfied::NotReady => MeshError::Lookup(format!(
                "mesh ident {:?} is deployed but not Ready; a requirement gates on \
                 Ready, not on presence (W338 §Ordering and readiness)",
                ident.0
            )),
            Unsatisfied::NotLocal {
                provider,
                this_node,
            } => MeshError::Lookup(format!(
                "mesh ident {:?} is required with locality = \"local\", which only a \
                 provider on THIS node satisfies, but the provider is on {} and this \
                 node is {}",
                ident.0,
                provider.map_or("an unknown node".to_string(), |ip| ip.to_string()),
                this_node.map_or("not on any mesh plane".to_string(), |ip| ip.to_string()),
            )),
        }
    }
}

/// Is one gated requirement satisfied by `state` right now? — W338's locality
/// table plus its Ready rule, in one place (R860-T2).
///
/// Three conditions, in order:
///
/// 1. **Presence.** A provider for the ident is known at all.
/// 2. **Readiness.** It reports Ready. W338: "a restore that is still replaying
///    a WAL is exactly the case where a bound port lies", so presence is not
///    enough for any locality.
/// 3. **Locality.** For [`Locality::Local`] only, the provider's node address
///    must equal this node's. [`Locality::Anywhere`] skips this — any Ready
///    provider counts. ([`Locality::PreferLocal`] never reaches here; see
///    [`gated_requirements`].)
///
/// **Locality fails closed.** If this node does not know its own mesh address,
/// or the state source cannot say which node a provider is on, a `local`
/// requirement is refused rather than quietly downgraded to `anywhere`. The
/// motivating case is a sqlite replicator that must open the same file on the
/// same filesystem as its requirer: satisfying that edge from another node is
/// not a scheduling inefficiency, it is data corruption. An unsatisfiable
/// requirement fails one deploy loudly; a silently-widened one succeeds and is
/// wrong.
fn requirement_satisfied(req: &Requirement, state: &dyn MeshState) -> Result<(), Unsatisfied> {
    let addr = state.lookup(&req.ident).ok_or(Unsatisfied::Absent)?;
    if !addr.ready {
        return Err(Unsatisfied::NotReady);
    }
    if req.locality == Locality::Local {
        let this_node = state.node_mesh_ip();
        match (this_node, addr.provider_mesh_ip) {
            (Some(mine), Some(theirs)) if mine == theirs => {}
            (this_node, provider) => {
                return Err(Unsatisfied::NotLocal {
                    provider,
                    this_node,
                })
            }
        }
    }
    Ok(())
}

/// Compute the dependency-wait deadline as the sum of each dep's
/// `dependency_wait_deadline`, defaulting to `default_per_dep` for any dep
/// not yet in `state` (or with no healthcheck).
///
/// Matches the arch doc rule "time out at sum(spec.depends_on healthchecks)"
/// — when a dep's healthcheck is known we use it, otherwise a fallback so
/// unknown deps don't make the wait infinite. Summed over
/// [`gated_requirements`], so the budget covers `requires` entries too and not
/// just the legacy field.
pub fn compute_dependency_deadline(
    spec: &WorkloadSpec,
    state: &dyn MeshState,
    default_per_dep: Duration,
) -> Duration {
    gated_requirements(spec)
        .iter()
        .map(|req| {
            state
                .lookup(&req.ident)
                .and_then(|a| a.dependency_wait_deadline)
                .unwrap_or(default_per_dep)
        })
        .sum()
}

/// Wait until every one of the spec's [`gated_requirements`] is **satisfied**
/// in `state`, or fail once `deadline` elapses with an error naming the first
/// unsatisfied one and why.
///
/// Satisfied means [`requirement_satisfied`] — Ready, and on this node when the
/// requirement says `local`. It is deliberately not "observable": a provider
/// that has appeared but is not Ready keeps this waiting, and a Ready provider
/// on another node does not satisfy a `local` edge at all (R860-T2, W338).
///
/// Polls every `poll_interval` (use [`DEFAULT_POLL_INTERVAL`] for the 250ms
/// production cadence). The first tick runs immediately so already-satisfied
/// dependencies don't pay the poll-interval cost.
///
/// Returns `Ok(())` immediately when nothing is gated — which includes every
/// spec whose only requirements are `self`-supplied or `prefer-local`; see
/// [`gated_requirements`] for why each is excluded.
///
/// @yah:ticket(R860-B3, "depends_on is NOT enforced: deploy::mesh_resolve has zero callers, so no deploy ever waits on a dependency")
/// @yah:status(review)
/// @yah:phase(P1)
/// @yah:at(2026-09-05T18:29:04Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R860)
/// @yah:severity(high)
/// @yah:verify("rg -n 'await_dependencies|impl .*MeshState|StateMeshResolver::new' --type rust oss/ app/ crates/ — must show production call sites outside mesh_resolve.rs, not just the module that defines them.")
/// @yah:gotcha("W338's \\\"What already exists\\\" table claims `depends_on` is **Enforced** — \\\"blocks a deploy until each dep appears in the service registry; deadline = sum of dep healthchecks\\\". That is false, and R860 was scoped on the assumption it was true. Correct the table row as part of this ticket; leaving it makes the next reader re-derive the same wrong premise.")
/// @arch:see(.yah/docs/working/W338-workload-dependencies-and-appliance-composition.md)
/// @yah:next("Evidence, verified 2026-09-04: `rg -n \"impl .*MeshState|await_dependencies|StateMeshResolver::new|InMemoryMeshState\" --type rust oss/ app/ crates/` returns NOTHING outside mesh_resolve.rs itself. The only MeshState impls are InMemoryMeshState (mesh_resolve.rs:145) and the DelayedAppearance test double (:448). deploy/mod.rs:33 already recorded half of this (\"deploy/mesh_resolve.rs also has zero callers in lib.rs by the same grep — candidate for a follow-up ticket\") and it was never picked up. So both halves of the module are dead: the FromMesh env resolver AND the dependency gate.")
/// @yah:next("Fix shape: give MeshState a production implementor backed by ServiceRecord (oss/yubaba/crates/yubaba/src/service_records.rs:363-377 — carries mesh_ip + resolved_ports + a ready flag), and call await_dependencies + StateMeshResolver from the node's deploy handler in oss/yubaba/crates/yubaba/src/lib.rs before the workload starts. NOTE that lib.rs is contended — @Ashguard:eclipse holds R858 in the neighbouring headscale files — so keep the edit to the deploy handler and coordinate before widening.")
/// @yah:handoff("LANDED — depends_on is enforced and FromMesh env is rendered, both from the real deploy path. Three files: (1) oss/yubaba/crates/yubaba/src/deploy/mesh_resolve.rs gained ServiceRecordMeshState, the production MeshState reading the node's ServiceRecords registry (the same registry GET /service-records serves); (2) oss/yubaba/crates/yubaba/src/lib.rs deploy_workload_spec now runs compute_dependency_deadline + await_dependencies + StateMeshResolver in the has-backend branch, immediately before rt.deploy_workload (lib.rs:3779-3846); (3) W338's table row corrected. The ticket's own verify criterion now passes: rg for await_dependencies/StateMeshResolver::new/impl MeshState shows production call sites in lib.rs, not just the defining module.")
/// @yah:next("R860-T2 picks up exactly here and nothing about this change forecloses its two axes. Ready-gating: swap ServiceRecordMeshState::lookup from ServiceRecords::get (any record, including NotReady and ledger-rehydrated ones) to a readiness-filtered read — the presence semantics are isolated to that one method and are documented as deliberate there. Locality: ServiceRecordMeshState already holds the ServiceRecord, so record.mesh_ip is in hand for the `local == record.mesh_ip == state.node_mesh_ip()` test T2's own notes describe; it will need the ServerState node_mesh_ip threaded into the adapter's constructor.")
/// @yah:verify("BASELINE, recorded before any edit: cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib = 681 passed / 0 failed. AFTER: 685 passed / 0 failed, run twice (the second run to clear a shared-tree input-skew warning naming peer edits in oss/yah-base/crates/{keys,workload-spec} that landed mid-run). +4 is exactly the four new tests and no pre-existing test changed verdict.")
/// @yah:handoff("DECISIONS THE BRIEF DID NOT COVER, all made rather than asked. (1) `MeshAddress` gained `dial_host: Option<String>` and `MeshLookup::Url` now renders that host when set. ServiceRecordMeshState sets it to the record's `mesh_ip`; the in-memory fake leaves it None and renders the ident exactly as before. Reason: NOTHING PUBLISHES MESH IDENTS INTO DNS on this fleet (checked — no extra_hosts / /etc/hosts injection / headscale record rail for workload idents; passway dials mesh_ip + port), so wiring the rail without this would have handed dependents `http://db:5432` and shipped an unreachable URL as the deliverable. `MeshLookup::Host` deliberately still answers the bare ident — workload-spec documents it as \"the DNS-ish identifier as authored\", and a caller asking for the NAME is not asking for an address, so R844-B22's canon is untouched. (2) `DEFAULT_DEPENDENCY_WAIT_PER_DEP = 30s`. (3) Gate failure = 424 FAILED_DEPENDENCY, env-resolution failure = 422; both reap the secret dir first when `secret_dir_is_new`, matching R848's existing guarded-reap rule on the neighbouring failure paths.")
/// @yah:gotcha("THE DEADLINE IS NOT WHAT W338 SAID AND CANNOT BE YET, so do not \"restore\" it. The old doc row promised `deadline = sum of dep healthchecks`; a ServiceRecord carries no healthcheck, so ServiceRecordMeshState reports `dependency_wait_deadline: None` for every dependency and compute_dependency_deadline falls back to DEFAULT_DEPENDENCY_WAIT_PER_DEP (30s) each time. Real budget is `depends_on.len() * 30s`. Making the promise true needs a spec-level source the registry does not have — the dep's own WorkloadSpec healthcheck — which is a different lookup, not a tweak.")
/// @yah:gotcha("TWO DEPLOY PATHS EXIST AND ONLY ONE IS GATED, stated so nobody reads \"depends_on is enforced\" wider than it is. The gate sits inside the has-backend branch of `deploy_workload_spec` (container tier). NOT gated: (a) stub mode, no backend attached — nothing starts, so there is nothing to order; (b) `deploy_non_container` (lib.rs:3238, the W272 bundle / MesofactStatic envelope), which returns before the container admission block entirely. A bundle declaring depends_on still waits for nothing. Separable and deliberately out of scope here.")
/// @yah:handoff("DISCOVERED WORK DONE IN THIS PASS, beyond the ticket title. (1) Three doc comments in mesh_resolve.rs asserted the production impl \"reads from raft\" / pointed at `crates/yah/yubaba/src/raft/` — false, and the file this ticket exists to un-deadify was the one telling the lie; corrected at the module doc, the MeshState trait doc and the InMemoryMeshState doc to name ServiceRecordMeshState. (2) W338 line 77 repeated the same false premise as the table row in prose (\"depends_on is the seed of the answer and is already enforced\"); corrected to \"enforced as of R860-B3\". The brief said keep the doc edit to one row — I made this second one-word change because leaving it would have had the paragraph contradict the row directly above it. Nothing else in W338 was restructured. (3) NOT done deliberately: R784's handoff in deploy/mod.rs:33 recorded this dead code as a never-picked-up followup and is now resolved by this ticket, but R784 is another ticket in `review` and I did not edit its annotation.")
/// @yah:verify("FOUR NEW TESTS, all driving POST /workloads/deploy through the real router against a recording `Kamaji` backend — a test calling await_dependencies directly would have passed for the last three relays and proved nothing, which is the whole bug. `a_deploy_whose_dependency_never_appears_is_refused_before_the_backend_is_called` (424 AND the backend recorded zero deploys — the load-bearing assertion), `a_dependency_present_in_the_service_records_satisfies_the_gate`, `from_mesh_env_is_rendered_from_the_service_record_before_the_backend_sees_it` (asserts the backend received `Literal { value: \"http://100.64.0.7:5432\" }`, never an unresolved FromMesh), `an_unresolvable_from_mesh_reference_rejects_the_deploy`. All are `#[tokio::test(start_paused = true)]` so the real 30s-per-dep budget elapses in zero wall time with the arithmetic still exercised.")
/// @yah:verify("WIDER: `cargo check --manifest-path oss/yubaba/Cargo.toml --workspace --all-targets` = 0 errors (covers every yubaba integration-test target; MeshAddress gained a field and is constructed in exactly one file, so this is the run that proves nothing outside it broke). Confirmed by grep that no existing test or caller sets a non-empty `depends_on` — every construction in oss/yubaba/crates/*/tests, oss/yubaba/crates/cloud/src and crates/yah/hub is `depends_on: vec![]`, and await_dependencies returns Ok immediately on an empty list, so no pre-existing deploy test can stall on the new gate. NOT RUN: no live fleet node, and no oss/yubaba integration-test suite was executed (only compiled).")
/// @yah:handoff("SHARED-TREE STATE, uncommitted. Three files carry my hunks and NOTHING was committed — peers wip-commit constantly here, so verify by content not by git status: oss/yubaba/crates/yubaba/src/deploy/mesh_resolve.rs (grep `ServiceRecordMeshState` / `dial_host` / `DEFAULT_DEPENDENCY_WAIT_PER_DEP`), oss/yubaba/crates/yubaba/src/lib.rs (grep `R860-B3` — one gate block at ~3779 in deploy_workload_spec, one test block at ~9598), .yah/docs/working/W338-workload-dependencies-and-appliance-composition.md (the depends_on table row + line 77). Tree anchor for the dispatch was 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2. NO COLLISION: @Ashguard:hydra relayed that @Ashguard:blade (session:6d887168) confirmed their lib.rs edit is only `pub mod cert_materialize;` plus a doc comment near line 402, and the R858 session's hunks are in headscale_deploy (~4674) and headscale_health_check (~4745) — all far from deploy_workload_spec and none of the five R858-held files were touched. Three sessions were in lib.rs concurrently, so any commit of this work must be pathspec-scoped.")
/// @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
/// @yah:handoff("LEADER RE-VERIFIED (session:69b18855, independent of the courier's self-report). `cargo test -p yubaba --lib` inside oss/yubaba: 685 passed / 0 failed, exit 0, against the courier's recorded 681/0 baseline — +4 = exactly its new tests. Wiring confirmed by content at yubaba/src/lib.rs:3781-3818: `ServiceRecordMeshState::new(&s.service_records)` :3785, `compute_dependency_deadline` :3786, `await_dependencies` :3791, `StateMeshResolver::new` :3818 — all inside `deploy_workload_spec`, after secret materialization and before `rt.deploy_workload`. The rail that had zero callers for its whole life now has a production one.")
/// @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
/// @yah:verify("cargo test -p yubaba --lib (inside oss/yubaba): 685 passed / 0 failed vs a 681/0 baseline. rg -n 'await_dependencies|ServiceRecordMeshState' oss/yubaba/crates/yubaba/src/lib.rs now returns production call sites at :3781-3818, which is what the ticket's own verify criterion demanded.")
/// @yah:handoff("W338 CORRECTED HONESTLY, and the correction is better than the ticket asked for. The table row now reads \\\"**Enforced since R860-B3 (2026-09-04), and not before it** — the gate existed but had zero callers, so until that ticket no deploy ever waited on anything\\\", and it names TWO further things the old row got wrong rather than only the one this ticket was filed on: satisfaction is **presence** in the registry, not readiness (a NotReady or ledger-rehydrated record counts — Ready-gating is R860-T2), and the deadline is **not** the sum of dep healthchecks, because a service record carries no healthcheck — every dep falls back to DEFAULT_DEPENDENCY_WAIT_PER_DEP (30s), so the budget is `depends_on.len() × 30s`. That second caveat retires a promise W338 made that the data model cannot keep.")
/// @yah:gotcha("SEAM THIS TICKET LEFT, CLOSED BY R860-T6. The gate wired here read `spec.depends_on` directly rather than `effective_requirements()`, so once R860-T1 landed `requires`, every requirement declared in the NEW vocabulary was gated on nothing — the rail was live but the widened field flowed past it. That was the leader's sequencing, not the courier's: B3's brief explicitly said \\\"Do not read `WorkloadSpec::requires` or `effective_requirements()` here even though R860-T1 just landed them\\\", deferring it to R860-T2. The window was real but closed inside the same relay — R860-T6 widened the gate as part of its provisioning pass. Recorded so a reader of B3 alone does not conclude the gate covers `requires`; it does now, because of T6.")
/// @yah:handoff("Tree anchor at handoff: 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2 — the shared tree as I left it. Diff against it (`git diff 0a85122cdb33dbf97ebc04b84e07d9cfc049c0b2..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
/// @yah:verify("RE-VERIFIED AT HEAD 00ee20d1 (session:aa5e882d, 2026-09-05). The rail that had zero callers is called: `ServiceRecordMeshState::new` at oss/yubaba/crates/yubaba/src/lib.rs:3999 and `await_dependencies` at :4008, inside `deploy_workload_spec`. `cargo test --manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 731 passed / 0 failed, exit 0 (was 708 at the prior re-verify; +23 are peers' tests landed since, not R860's). CAVEAT, stated rather than hidden: the camp build rail's skew verdict flagged oss/yubaba/crates/yubaba/src/acme_issuer.rs as modified by a peer mid-run — an ACME file, outside this ticket's deploy/ closure, and the run compiled and ran to completion.")
pub async fn await_dependencies(
    spec: &WorkloadSpec,
    state: &dyn MeshState,
    deadline: Duration,
    poll_interval: Duration,
) -> Result<(), MeshError> {
    let gated = gated_requirements(spec);
    if gated.is_empty() {
        return Ok(());
    }
    let start = Instant::now();
    loop {
        let unsatisfied = gated
            .iter()
            .find_map(|req| requirement_satisfied(req, state).err().map(|why| (req, why)));
        match unsatisfied {
            None => return Ok(()),
            Some((req, why)) if start.elapsed() >= deadline => {
                return Err(why.into_error(&req.ident));
            }
            Some(_) => tokio::time::sleep(poll_interval).await,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod mesh {
    mod resolve {
        //! Fake-raft-state coverage for Url/Host/Port + waiting-for-dependency
        //! + timeout-after-deps-deadline.

        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use workload_spec::validate::{MeshError, MeshResolver};
        use workload_spec::*;

        use crate::deploy::mesh_resolve::{
            await_dependencies, compute_dependency_deadline, InMemoryMeshState, MeshAddress,
            MeshState, StateMeshResolver,
        };

        // ── Minimal spec helper ──────────────────────────────────────────────

        fn spec_with_depends_on(deps: Vec<MeshIdent>) -> WorkloadSpec {
            WorkloadSpec {
                schema_version: SchemaVersion::V1,
                name: "consumer".into(),
                image: ImageRef {
                    registry: "ghcr.io".into(),
                    repository: "test/consumer".into(),
                    tag: "v1".into(),
                    digest: workload_spec::testing::test_digest(),
                },
                tier: TierTag("private".into()),
                tenant: workload_spec::TenantId::singleton(),
                namespace: workload_spec::NamespaceId::singleton(),
                replicas: 1,
                command: None,
                entrypoint: None,
                workdir: None,
                user: None,
                env: vec![],
                secrets: vec![],
                volumes: vec![],
                resources: ResourceLimits {
                    memory_mb: 64,
                    cpu_millis: 256,
                    ephemeral_storage_mb: 64,
                },
                depends_on: deps,
                requires: vec![],
                healthcheck: None,
                restart_policy: RestartPolicy::Always,
                archetype: None,
                stop_policy: StopPolicy {
                    signal: 15,
                    grace_period: Millis::from_secs(5),
                },
                expose: ExposeSpec {
                    mesh: MeshExpose {
                        identity: MeshIdent("consumer".into()),
                        ports: MeshExpose::anonymous_ports([8080]),
                        allow_from: vec![],
                    },
                    public: None,
                    operator: None,
                },
                labels: HashMap::new(),
                annotations: HashMap::new(),
            }
        }

        fn ports(pairs: &[(&str, u16)]) -> std::collections::BTreeMap<String, u16> {
            pairs.iter().map(|(n, p)| ((*n).to_string(), *p)).collect()
        }

        fn db_address() -> MeshAddress {
            MeshAddress {
                ident: MeshIdent("noisetable-db.pdx".into()),
                dial_host: None,
                provider_mesh_ip: None,
                ready: true,
                ports: ports(&[("http", 5432)]),
                dependency_wait_deadline: Some(Duration::from_secs(45)),
            }
        }

        // ── Url / Host / Port ────────────────────────────────────────────────

        #[test]
        fn url_renders_the_selected_port_with_http_prefix() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let resolver = StateMeshResolver::new(&state);
            let value = resolver
                .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Url)
                .expect("resolve");
            assert_eq!(value, "http://noisetable-db.pdx:5432");
        }

        /// R844-B22: `db_address` used to expose `[5432, 9100]` and this file
        /// asserted `Url` rendered 5432 — the first entry, i.e. a coin flip the
        /// test then locked in. A multi-listener peer with no `http` now has to
        /// be asked which one.
        #[test]
        fn several_unnamed_ports_error_rather_than_resolving_to_the_first() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("multi.pdx".into()),
                dial_host: None,
                provider_mesh_ip: None,
                ready: true,
                ports: ports(&[("5432", 5432), ("9100", 9100)]),
                dependency_wait_deadline: None,
            });
            let resolver = StateMeshResolver::new(&state);
            let err = resolver
                .resolve(&MeshIdent("multi.pdx".into()), MeshLookup::Url)
                .unwrap_err();
            assert!(
                matches!(err, MeshError::AmbiguousPort { .. }),
                "expected AmbiguousPort, got {err:?}"
            );
        }

        /// And the spelling that answers it, end to end through the production
        /// resolver rather than the fake in workload-spec's own tests.
        #[test]
        fn a_named_lookup_selects_that_port_through_the_state_resolver() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("api.pdx".into()),
                dial_host: None,
                provider_mesh_ip: None,
                ready: true,
                ports: ports(&[("http", 8080), ("wss", 8443)]),
                dependency_wait_deadline: None,
            });
            let resolver = StateMeshResolver::new(&state);
            assert_eq!(
                resolver
                    .resolve(
                        &MeshIdent("api.pdx".into()),
                        MeshLookup::UrlNamed {
                            name: "wss".into()
                        }
                    )
                    .expect("resolve"),
                "http://api.pdx:8443"
            );
            // The unnamed form still answers, via `http`, not via position.
            assert_eq!(
                resolver
                    .resolve(&MeshIdent("api.pdx".into()), MeshLookup::Port)
                    .expect("resolve"),
                "8080"
            );
        }

        #[test]
        fn host_renders_bare_ident() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let resolver = StateMeshResolver::new(&state);
            let value = resolver
                .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Host)
                .expect("resolve");
            assert_eq!(value, "noisetable-db.pdx");
        }

        #[test]
        fn port_renders_first_port_as_string() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let resolver = StateMeshResolver::new(&state);
            let value = resolver
                .resolve(&MeshIdent("noisetable-db.pdx".into()), MeshLookup::Port)
                .expect("resolve");
            assert_eq!(value, "5432");
        }

        #[test]
        fn unknown_ident_returns_not_deployed() {
            let state = InMemoryMeshState::new();
            let resolver = StateMeshResolver::new(&state);
            let err = resolver
                .resolve(&MeshIdent("absent.pdx".into()), MeshLookup::Url)
                .unwrap_err();
            assert_eq!(
                err,
                MeshError::NotDeployed {
                    ident: "absent.pdx".into()
                }
            );
        }

        #[test]
        fn deployed_but_no_ports_returns_no_ports_for_url_and_port_lookups() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("portless".into()),
                dial_host: None,
                provider_mesh_ip: None,
                ready: true,
                ports: std::collections::BTreeMap::new(),
                dependency_wait_deadline: None,
            });
            let resolver = StateMeshResolver::new(&state);

            assert_eq!(
                resolver
                    .resolve(&MeshIdent("portless".into()), MeshLookup::Url)
                    .unwrap_err(),
                MeshError::NoPorts {
                    ident: "portless".into(),
                    lookup: MeshLookup::Url,
                }
            );
            assert_eq!(
                resolver
                    .resolve(&MeshIdent("portless".into()), MeshLookup::Port)
                    .unwrap_err(),
                MeshError::NoPorts {
                    ident: "portless".into(),
                    lookup: MeshLookup::Port,
                }
            );
            // Host doesn't need a port and still resolves
            assert_eq!(
                resolver
                    .resolve(&MeshIdent("portless".into()), MeshLookup::Host)
                    .expect("host resolve"),
                "portless"
            );
        }

        // ── Wait for dependency ──────────────────────────────────────────────

        /// `MeshState` impl that flips an ident from absent to present after
        /// `appear_after` polls. Used by the wait-for-dep test.
        #[derive(Clone)]
        struct DelayedAppearance {
            counter: Arc<Mutex<u32>>,
            appear_after: u32,
            ident: MeshIdent,
            address: MeshAddress,
        }

        impl MeshState for DelayedAppearance {
            fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress> {
                if ident.0 != self.ident.0 {
                    return None;
                }
                let mut count = self.counter.lock().unwrap();
                *count += 1;
                if *count > self.appear_after {
                    Some(self.address.clone())
                } else {
                    None
                }
            }

            fn node_mesh_ip(&self) -> Option<std::net::Ipv4Addr> {
                None
            }
        }

        #[tokio::test]
        async fn await_dependencies_returns_ok_when_dep_appears_during_polling() {
            let state = DelayedAppearance {
                counter: Arc::new(Mutex::new(0)),
                appear_after: 3, // present on the 4th poll
                ident: MeshIdent("noisetable-db.pdx".into()),
                address: db_address(),
            };
            let spec = spec_with_depends_on(vec![MeshIdent("noisetable-db.pdx".into())]);

            let result = await_dependencies(
                &spec,
                &state,
                Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .await;
            assert!(
                result.is_ok(),
                "expected Ok once dep appears, got {result:?}"
            );
            assert!(
                *state.counter.lock().unwrap() >= 4,
                "polled at least 4 times before resolving"
            );
        }

        #[tokio::test]
        async fn await_dependencies_returns_ok_immediately_when_already_deployed() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address());
            let spec = spec_with_depends_on(vec![MeshIdent("noisetable-db.pdx".into())]);

            let result = await_dependencies(
                &spec,
                &state,
                Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .await;
            assert!(result.is_ok(), "expected Ok, got {result:?}");
        }

        #[tokio::test]
        async fn await_dependencies_returns_ok_for_empty_deps() {
            let state = InMemoryMeshState::new();
            let spec = spec_with_depends_on(vec![]);
            let result = await_dependencies(
                &spec,
                &state,
                Duration::from_millis(1),
                Duration::from_millis(1),
            )
            .await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn await_dependencies_times_out_after_deps_deadline() {
            let state = InMemoryMeshState::new(); // dep never appears
            let spec = spec_with_depends_on(vec![MeshIdent("never-deploys".into())]);
            let err = await_dependencies(
                &spec,
                &state,
                Duration::from_millis(20),
                Duration::from_millis(1),
            )
            .await
            .unwrap_err();
            assert_eq!(
                err,
                MeshError::NotDeployed {
                    ident: "never-deploys".into()
                }
            );
        }

        #[tokio::test]
        async fn await_dependencies_times_out_on_first_missing_when_others_known() {
            let mut state = InMemoryMeshState::new();
            state.insert(db_address()); // first dep present
            let spec = spec_with_depends_on(vec![
                MeshIdent("noisetable-db.pdx".into()),
                MeshIdent("never-deploys".into()),
            ]);
            let err = await_dependencies(
                &spec,
                &state,
                Duration::from_millis(20),
                Duration::from_millis(1),
            )
            .await
            .unwrap_err();
            assert_eq!(
                err,
                MeshError::NotDeployed {
                    ident: "never-deploys".into()
                }
            );
        }

        // ── R860-T2: locality and Ready ──────────────────────────────────────
        //
        // W338's locality table and its "gate on Ready, not on presence" rule.
        // Each test states a requirement, a world, and asserts on whether the
        // gate BLOCKS — never on the helper that computes it.

        const THIS_NODE: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 7);
        const OTHER_NODE: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 9);

        fn requirement(ident: &str, locality: Locality) -> Requirement {
            Requirement {
                ident: MeshIdent(ident.into()),
                locality,
                supply: Supply::Wait,
                provides: None,
            }
        }

        fn spec_requiring(reqs: Vec<Requirement>) -> WorkloadSpec {
            let mut spec = spec_with_depends_on(vec![]);
            spec.requires = reqs;
            spec
        }

        /// A provider ident served from `node`.
        fn provider_on(ident: &str, node: std::net::Ipv4Addr, ready: bool) -> MeshAddress {
            MeshAddress {
                ident: MeshIdent(ident.into()),
                dial_host: Some(node.to_string()),
                provider_mesh_ip: Some(node),
                ready,
                ports: ports(&[("http", 5432)]),
                dependency_wait_deadline: None,
            }
        }

        /// Run the gate against a world that never changes, with a deadline
        /// short enough that "blocks" is observable as a timeout.
        async fn gate(spec: &WorkloadSpec, state: &dyn MeshState) -> Result<(), MeshError> {
            await_dependencies(
                spec,
                state,
                Duration::from_millis(20),
                Duration::from_millis(1),
            )
            .await
        }

        /// The load-bearing case. A `local` requirement satisfied by a provider
        /// on a DIFFERENT node used to pass — the gate did a plain presence
        /// check for every locality. W338: "Only a provider on **this node**
        /// satisfies it." The motivating edge is a sqlite replicator that must
        /// open the same file on the same filesystem, so admitting a remote
        /// provider here is silent data corruption, not a scheduling
        /// inefficiency.
        #[tokio::test]
        async fn a_local_requirement_is_not_satisfied_by_a_ready_provider_on_another_node() {
            let mut state = InMemoryMeshState::new().with_node_mesh_ip(THIS_NODE);
            state.insert(provider_on("replicator", OTHER_NODE, true));
            let spec = spec_requiring(vec![requirement("replicator", Locality::Local)]);

            let err = gate(&spec, &state).await.unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("replicator") && msg.contains("local") && msg.contains("100.64.0.9"),
                "the refusal must name the ident, the locality and the node the \
                 provider is actually on; got: {msg}"
            );
        }

        #[tokio::test]
        async fn a_local_requirement_is_satisfied_by_a_provider_on_this_node() {
            let mut state = InMemoryMeshState::new().with_node_mesh_ip(THIS_NODE);
            state.insert(provider_on("replicator", THIS_NODE, true));
            let spec = spec_requiring(vec![requirement("replicator", Locality::Local)]);

            assert!(
                gate(&spec, &state).await.is_ok(),
                "a provider on this node is exactly what `local` asks for"
            );
        }

        /// Fail closed. A node that does not know its own mesh address cannot
        /// decide locality, and the safe answer is "unsatisfiable" — degrading
        /// to `anywhere` would place the sidecar edge anywhere at all.
        #[tokio::test]
        async fn a_local_requirement_is_unsatisfiable_when_this_node_has_no_mesh_address() {
            let mut state = InMemoryMeshState::new(); // node_mesh_ip: None
            state.insert(provider_on("replicator", THIS_NODE, true));
            let spec = spec_requiring(vec![requirement("replicator", Locality::Local)]);

            let msg = gate(&spec, &state).await.unwrap_err().to_string();
            assert!(
                msg.contains("not on any mesh plane"),
                "the refusal must say the NODE could not answer, not that the \
                 provider was missing; got: {msg}"
            );
        }

        /// The other half of the table: `anywhere` is unchanged by the locality
        /// work — any Ready provider satisfies it, including a remote one.
        #[tokio::test]
        async fn an_anywhere_requirement_is_satisfied_by_a_provider_on_another_node() {
            let mut state = InMemoryMeshState::new().with_node_mesh_ip(THIS_NODE);
            state.insert(provider_on("db", OTHER_NODE, true));
            let spec = spec_requiring(vec![requirement("db", Locality::Anywhere)]);

            assert!(gate(&spec, &state).await.is_ok(), "`anywhere` means anywhere");
        }

        /// W338 §Ordering and readiness: "a restore that is still replaying a
        /// WAL is exactly the case where a bound port lies". The record is
        /// present — `lookup` answers — and the gate must still block.
        #[tokio::test]
        async fn a_present_but_not_ready_provider_does_not_satisfy_a_requirement() {
            let mut state = InMemoryMeshState::new().with_node_mesh_ip(THIS_NODE);
            state.insert(provider_on("db", THIS_NODE, false));
            let spec = spec_requiring(vec![requirement("db", Locality::Anywhere)]);

            let msg = gate(&spec, &state).await.unwrap_err().to_string();
            assert!(
                msg.contains("not Ready"),
                "presence is not readiness, and the refusal must say which it \
                 failed; got: {msg}"
            );
        }

        /// Readiness applies to the legacy field too — `depends_on` folds in as
        /// `anywhere` + `wait`, so it is gated by the same rule.
        #[tokio::test]
        async fn a_not_ready_provider_blocks_a_legacy_depends_on_entry_too() {
            let mut state = InMemoryMeshState::new().with_node_mesh_ip(THIS_NODE);
            state.insert(provider_on("db", THIS_NODE, false));
            let spec = spec_with_depends_on(vec![MeshIdent("db".into())]);

            assert!(gate(&spec, &state).await.is_err());
        }

        /// `prefer-local`'s defining property is that it never blocks
        /// placement — not even when no provider exists anywhere. Unchanged by
        /// this ticket, asserted because the locality work is exactly what
        /// could have broken it.
        #[tokio::test]
        async fn a_prefer_local_requirement_never_blocks_even_with_no_provider_at_all() {
            let state = InMemoryMeshState::new().with_node_mesh_ip(THIS_NODE);
            let spec = spec_requiring(vec![requirement("cache", Locality::PreferLocal)]);

            assert!(gate(&spec, &state).await.is_ok());
        }

        /// A provider that becomes Ready during the wait releases the gate —
        /// the gate polls satisfaction, it does not sample it once.
        #[tokio::test]
        async fn a_requirement_is_released_once_its_provider_turns_ready() {
            struct BecomesReady {
                polls: Arc<Mutex<u32>>,
                ready_after: u32,
            }
            impl MeshState for BecomesReady {
                fn lookup(&self, ident: &MeshIdent) -> Option<MeshAddress> {
                    let mut n = self.polls.lock().unwrap();
                    *n += 1;
                    Some(MeshAddress {
                        ident: ident.clone(),
                        dial_host: None,
                        provider_mesh_ip: Some(THIS_NODE),
                        ready: *n > self.ready_after,
                        ports: std::collections::BTreeMap::new(),
                        dependency_wait_deadline: None,
                    })
                }
                fn node_mesh_ip(&self) -> Option<std::net::Ipv4Addr> {
                    Some(THIS_NODE)
                }
            }

            let state = BecomesReady {
                polls: Arc::new(Mutex::new(0)),
                ready_after: 3,
            };
            let spec = spec_requiring(vec![requirement("db", Locality::Local)]);
            let result = await_dependencies(
                &spec,
                &state,
                Duration::from_secs(5),
                Duration::from_millis(1),
            )
            .await;
            assert!(result.is_ok(), "expected Ok once ready, got {result:?}");
            assert!(*state.polls.lock().unwrap() >= 4, "must have kept polling");
        }

        // ── compute_dependency_deadline ──────────────────────────────────────

        #[test]
        fn deadline_sums_known_dep_healthchecks_and_falls_back_to_default() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("a".into()),
                dial_host: None,
                provider_mesh_ip: None,
                ready: true,
                ports: ports(&[("http", 1)]),
                dependency_wait_deadline: Some(Duration::from_secs(10)),
            });
            state.insert(MeshAddress {
                ident: MeshIdent("b".into()),
                dial_host: None,
                provider_mesh_ip: None,
                ready: true,
                ports: ports(&[("http", 2)]),
                dependency_wait_deadline: Some(Duration::from_secs(15)),
            });
            // c is not registered, so default applies.
            let spec = spec_with_depends_on(vec![
                MeshIdent("a".into()),
                MeshIdent("b".into()),
                MeshIdent("c".into()),
            ]);

            let deadline = compute_dependency_deadline(&spec, &state, Duration::from_secs(20));
            assert_eq!(deadline, Duration::from_secs(10 + 15 + 20));
        }

        #[test]
        fn deadline_uses_default_when_dep_lacks_healthcheck() {
            let mut state = InMemoryMeshState::new();
            state.insert(MeshAddress {
                ident: MeshIdent("a".into()),
                dial_host: None,
                provider_mesh_ip: None,
                ready: true,
                ports: ports(&[("http", 1)]),
                dependency_wait_deadline: None, // dep deployed but has no healthcheck
            });
            let spec = spec_with_depends_on(vec![MeshIdent("a".into())]);
            let deadline = compute_dependency_deadline(&spec, &state, Duration::from_secs(7));
            assert_eq!(deadline, Duration::from_secs(7));
        }
    }
}
