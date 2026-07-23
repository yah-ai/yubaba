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

use anyhow::{bail, Result};
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
            hostkey_fingerprint: None,
            ssh_keys: vec![],
            cloudflared: None,
            hosts_operator_bridge: false,
            connect: None,
            allocatable: None,
            taints: vec![],
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
        assert!(msg.contains("zone"), "expected a zone-mismatch message, got: {msg}");
        assert_eq!(
            provider.reassign_calls.load(Ordering::SeqCst),
            0,
            "zone mismatch must never call reassign"
        );
    }
}
