//! Provider-abstracted floating/reserved-IP mobility and ingress failover
//! (R594-F5, R859-F2).
//!
//! [`FloatingIpProvider`] is the domain-level trait each vendor adapter
//! implements; [`reconcile_assignment`] is the shared idempotent + zone-checked
//! core all of them run through, so the "no-op when already assigned" /
//! "reject a cross-zone move" behaviour is written and tested exactly once
//! instead of once per vendor. [`plan_ingress_owner_effect`] is the pure
//! decision layer above them: given a raft `ingress_owner` observation, what
//! should public ingress do?
//!
//! # Why this is its own crate
//!
//! It was `cloud::provider::floating_ip` until 2026-09-08. R859-F2 landed
//! [`plan_ingress_owner_effect`] with no production caller, because the caller
//! belongs in `yubaba`'s scheduler tick and a runtime `yubaba -> cloud`
//! dependency was not a courier's call to make: `cloud/Cargo.toml`'s
//! `yah-local-driver` comment records R374-F3 carving *that* crate out of
//! `cloud` specifically to avoid such an edge, and taking it here would pull
//! velveteen, velveteen-exec, yah-hetzner, yah-mesofact-bundle and yah-almanac
//! into the release daemon shipped to every fleet node. The operator's answer
//! (2026-09-08) was to repeat R374-F3's move rather than reverse it — hence
//! this crate, which both `cloud` and `yubaba` depend on and neither owns.
//!
//! So the dependency budget here is load-bearing, not tidiness: `anyhow` and
//! `async-trait`, and nothing else, forever. A `reqwest` or a `serde` in this
//! manifest ships to every node in the fleet.
//!
//! # What is above this crate, and where
//!
//! Two consumers, and this crate depends on neither:
//!
//! - `yah-floating-ip-adapters` — the Hetzner/OVH/Vultr HTTP clients that
//!   implement [`FloatingIpProvider`]. They were in `cloud` until R859-F3 moved
//!   them one layer down so `yubaba`'s ingress effector could actually issue a
//!   reassign rather than only decide on one. That crate carries the `reqwest`
//!   this one refuses to.
//! - `yah-cloud` — the `floating_ip.*` envoy verb layer
//!   (`cloud::provider::floating_ip_envoy`) and the credentialed constructor
//!   `cloud::provider::floating_ip::floating_ip_provider_for`, which resolves
//!   vault slots through `fob`. Neither an envoy catalog nor a credential vault
//!   belongs on a fleet node, so neither moved.
//!
//! This crate holds the seam, the shared core, and the decision logic.
//!
//! # The machine facts this layer needs
//!
//! [`FloatingIpMachine`] is a five-field value, not `cloud`'s `MachineConfig`.
//! That is what makes the crate free of `cloud`: the adapters only ever read
//! `name`, `location`, `region`, `provider` and `ingress_floating_ip` off a
//! machine, so those five fields are the whole of the contract. `cloud`
//! converts at the boundary (`impl From<&MachineConfig> for FloatingIpMachine`)
//! and `yubaba` can build one from whatever it knows about a node without
//! being able to construct a `MachineConfig` at all — which it cannot, since a
//! fleet node has no `.yah/infra/machines/` tree.
//!
//! This mirrors, at the sovereign-ingress tier, the "external identity follows
//! placement" property [R591](yah://arch/symbol/R591) names for Headscale via a
//! Cloudflare Tunnel.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

/// The machine facts floating-IP mobility actually needs — the whole contract
/// between this crate and whatever declares machines.
///
/// Five fields because five is what the vendor adapters read. Keeping it a
/// value type rather than borrowing `cloud`'s `MachineConfig` is the thing that
/// lets `yubaba` link this crate: a fleet node has no `.yah/infra/machines/`
/// tree and could not build a `MachineConfig` if it wanted to, but it can name
/// a machine and say which provider hosts it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FloatingIpMachine {
    /// Declared machine name. Every adapter's `resolve_target` looks the box up
    /// by this: Hetzner `?name=`, Vultr `?label=`, OVH `serviceName`.
    pub name: String,
    /// Provider id — `"hetzner"`, `"ovh"`, `"vultr"`. Selects the adapter.
    pub provider: String,
    /// Provider DC code. `None` for static nodes.
    pub location: Option<String>,
    /// Coarser provider region, used by OVH when `location` is absent.
    pub region: Option<String>,
    /// Which floating/reserved IP follows public ingress onto this machine.
    /// `None` is the common case and a supported shape: a fleet whose ingress
    /// moves by DNS alone has no floating IP anywhere.
    pub ingress_floating_ip: Option<String>,
}

impl FloatingIpMachine {
    /// Provider DC code, or `""` when omitted — mirrors
    /// `cloud::config::MachineConfig::location()` so a moved adapter reads the
    /// same.
    pub fn location(&self) -> &str {
        self.location.as_deref().unwrap_or("")
    }
}

/// One provider's floating/reserved-IP transport + mobility policy.
///
/// Implementors ship in `yah-floating-ip-adapters`: `HetznerFloatingIp`,
/// `OvhFloatingIp`, `VultrFloatingIp` (R859-F3).
#[async_trait]
pub trait FloatingIpProvider: Send + Sync {
    /// Provider id, e.g. `"hetzner"` — matches
    /// [`FloatingIpMachine::provider`].
    fn id(&self) -> &'static str;

    /// Resolve a target machine into this provider's native attach
    /// identifier (server id / serviceName / instance UUID) plus the
    /// mobility zone it lives in. May hit the provider's API (e.g. a
    /// name→id lookup) — this is a live-data resolution step, not a pure
    /// function of the declaration.
    async fn resolve_target(&self, machine: &FloatingIpMachine) -> Result<FloatingIpTarget>;

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
///
/// Generic over `?Sized` so it accepts both a concrete adapter and a
/// `&dyn FloatingIpProvider` (R859-F3): `cloud`'s blanket `FloatingIpEnvoy`
/// impl covers `dyn FloatingIpProvider` itself, and a `&dyn` cannot be
/// re-unsized to `&dyn` under a `Sized` bound.
pub async fn reconcile_assignment<P: FloatingIpProvider + ?Sized>(
    provider: &P,
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
/// This is the *applier*; [`plan_ingress_owner_effect`] is the decision that
/// should precede it. Calling this directly skips every guard rail R859-F2
/// wrote (quorum gate, liveness veto, owner resolution) — do that only from an
/// operator-driven path where a human has already made the call.
///
/// `ClearIngressOwner` (`ingress_owner` going to `None`) has no defined
/// action — there is no "detach the IP" verb because Tier 1 has no
/// specified safe-unassigned state, and leaving the IP on the last-known-good
/// node is the correct default. So this function is only meaningful for
/// `Some(machine)` transitions; [`plan_ingress_owner_effect`] encodes the same
/// conclusion as a [`NoOp`](IngressOwnerEffect::NoOp).
pub async fn on_ingress_owner_changed<P: FloatingIpProvider + ?Sized>(
    provider: &P,
    machine: &FloatingIpMachine,
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
/// it and they must not drift: `cloud`'s `floating_ip_provider_for` builds the
/// adapter from the slot/env pair, and [`provider_has_floating_ip_adapter`]
/// answers the same question *without* credentials, for `yah cloud validate`
/// (which runs on an operator's laptop with no fleet tokens loaded and must
/// still be able to refuse a machine declaring a floating IP its provider
/// cannot move).
///
/// Public because the constructor that reads the slot/env columns lives in
/// `cloud` now — the table has to cross the crate boundary to keep being one
/// table.
pub const FLOATING_IP_PROVIDERS: &[(&str, &str, &str)] = &[
    ("hetzner", "hetzner-api-token", "HETZNER_API_TOKEN"),
    ("ovh", "ovh-consumer-key", "OVH_CONSUMER_KEY"),
    ("vultr", "vultr-api-key", "VULTR_API_KEY"),
];

/// Does `provider` have a floating-IP adapter at all?
///
/// Credential-free by design — see [`FLOATING_IP_PROVIDERS`]. A `false` here
/// means [`FloatingIpMachine::ingress_floating_ip`] on such a machine could
/// never be acted on, which is a declaration worth refusing at validate time
/// rather than discovering during a failover.
pub fn provider_has_floating_ip_adapter(provider: &str) -> bool {
    FLOATING_IP_PROVIDERS.iter().any(|(id, _, _)| *id == provider)
}

/// The provider ids that ship an adapter, for an error message that names what
/// *is* supported rather than only what is not.
pub fn supported_floating_ip_providers() -> String {
    FLOATING_IP_PROVIDERS
        .iter()
        .map(|(id, _, _)| *id)
        .collect::<Vec<_>>()
        .join(", ")
}

// ── R859-F2: the pure ingress-owner effect planner ────────────────────────

/// What a `TransitionTracker`-style hysteresis says about one machine, crossed
/// into this crate as plain data.
///
/// The yubaba-side original is
/// `yubaba::lease_detector::TransitionTracker::committed`, which answers
/// `Option<Confirmed>`. It is re-spelled rather than imported because this
/// crate sits *below* both consumers and must not depend on either. The
/// crossing is by value.
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
        /// Its [`FloatingIpMachine::ingress_floating_ip`].
        ip_id: String,
    },
    /// Drop `machine` from the apex origin set — the cross-provider failover.
    ///
    /// Consumed by `cloud::reconciler::domain::public_origins`'s
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
    machines: &'a [FloatingIpMachine],
) -> Result<&'a FloatingIpMachine> {
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
/// (`plan_domain_passway` vs `deploy_domain_passway`), and the same one
/// `yubaba`'s `scheduler::decide_transfer` uses. Nothing here touches a
/// network, a clock or a config file.
///
/// # The gating rule: fail-closed on withdrawal, fail-open on addition
///
/// Deliberately the same rule R859-F1 wrote for its apex prune
/// (`DomainPasswayPlan::origins_complete`), and cited here so the two stay one
/// rule rather than two coincidences. Taking something *away* — an IP off the
/// box currently serving it, an A record out of the round-robin — on evidence
/// we are not sure of is how a leadership flap becomes a public outage. Adding
/// can never make the apex worse. So:
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
    machines: &[FloatingIpMachine],
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
    /// tests in `yah-floating-ip-adapters`'s `hetzner.rs` / `ovh.rs` /
    /// `vultr.rs` cover the wire-level shape).
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
        async fn resolve_target(&self, machine: &FloatingIpMachine) -> Result<FloatingIpTarget> {
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

    fn machine(name: &str) -> FloatingIpMachine {
        FloatingIpMachine {
            name: name.into(),
            provider: "fake".into(),
            ..Default::default()
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

    /// The registry table and the error message that lists it are read by two
    /// crates now, so a row added here with no constructor in `cloud` would be
    /// a silent half-registration. This pins the join: every id the table
    /// advertises appears in the string the refusal shows an operator.
    #[test]
    fn every_registered_provider_is_named_in_the_supported_list() {
        let supported = supported_floating_ip_providers();
        for (id, _, _) in FLOATING_IP_PROVIDERS {
            assert!(supported.contains(id), "{id} missing from {supported:?}");
        }
    }

    // ── R859-F2: plan_ingress_owner_effect ────────────────────────────────

    fn fleet() -> Vec<FloatingIpMachine> {
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
