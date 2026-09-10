//! The `floating_ip.*` envoy layer over `yah-floating-ip-adapters` (R859-F3).
//!
//! Three vendor clients used to live in `provider/{hetzner,ovh,vultr}_floating_ip.rs`,
//! each being two things at once: a `FloatingIpProvider` (transport) and an
//! [`EnvoyAdapter`] (a dispatchable `floating_ip.assign` / `floating_ip.status`
//! verb pair). R859-F3 split them along that seam — the transport half is now
//! `floating_ip_adapters`, which the fleet daemon can link; the envoy half is
//! this module, which it cannot and should not.
//!
//! # The three copies became one
//!
//! Each adapter carried a byte-identical `floating_ip_assign` /
//! `floating_ip_status` pair and a byte-identical `dispatch` body — three
//! copies of code that only ever differed in the error string. They are
//! [`FloatingIpEnvoy`] and [`dispatch_floating_ip_verb`] here, written once
//! over `dyn FloatingIpProvider`, which is why moving the transports out was a
//! simplification rather than a shuffle.
//!
//! [`FloatingIpEnvoy`] is a *trait* rather than three inherent method pairs
//! specifically because the vendor types are now foreign: Rust forbids an
//! inherent impl on a foreign type, but a local trait on a foreign type is
//! exactly what the orphan rule permits. Same reason the three [`EnvoyAdapter`]
//! impls below are legal.
//!
//! # What did NOT collapse, and why
//!
//! The three [`EnvoyAdapter`] impls are written out rather than blanketed over
//! `T: FloatingIpProvider`, for two reasons that are both about the envoy layer
//! and not about the transports: the tiers genuinely differ (Hetzner and Vultr
//! are `Tier::S`, OVH is `Tier::A` because its auth is a placeholder — see the
//! `ovh` adapter's module doc), and a blanket [`EnvoyAdapter`] impl would claim
//! every present and future `FloatingIpProvider` implementor, including a test
//! double, as a dispatchable envoy adapter. Three six-line impls are cheaper
//! than that coherence surface.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde_json::Value;

use crate::envoy::floating_ip::{
    FloatingIpAssign, FloatingIpAssignInput, FloatingIpAssignOutput, FloatingIpStatus,
    FloatingIpStatusInput, FloatingIpStatusOutput,
};
use crate::envoy::{AdapterFlavor, EnvoyAdapter, InternalVerb, Tier};
use floating_ip::{FloatingIpProvider, FloatingIpTarget};
use floating_ip_adapters::{HetznerFloatingIp, OvhFloatingIp, VultrFloatingIp};

/// The typed (non-JSON) `floating_ip.*` handlers, for callers and tests that
/// want to bypass the envelope.
///
/// Blanket-implemented for every [`FloatingIpProvider`], because the two
/// handlers are pure translation between the wire types and the seam — there
/// has never been a per-vendor difference in them, and the three copies that
/// preceded this were identical byte for byte.
#[async_trait]
pub trait FloatingIpEnvoy {
    /// `floating_ip.assign` — move the IP, idempotently and zone-checked.
    async fn floating_ip_assign(
        &self,
        input: FloatingIpAssignInput,
    ) -> Result<FloatingIpAssignOutput>;

    /// `floating_ip.status` — report where the IP lives today.
    async fn floating_ip_status(
        &self,
        input: FloatingIpStatusInput,
    ) -> Result<FloatingIpStatusOutput>;
}

#[async_trait]
impl<T: FloatingIpProvider + ?Sized> FloatingIpEnvoy for T {
    async fn floating_ip_assign(
        &self,
        input: FloatingIpAssignInput,
    ) -> Result<FloatingIpAssignOutput> {
        let target = FloatingIpTarget {
            attach_id: input.attach_id,
            zone: input.zone,
        };
        // The idempotency short-circuit and the cross-zone refusal are here,
        // once, for all three vendors — see `floating_ip::reconcile_assignment`.
        let outcome = floating_ip::reconcile_assignment(self, &input.ip_id, &target).await?;
        Ok(FloatingIpAssignOutput {
            reassigned: outcome.reassigned,
            attached_to: outcome.attached_to,
        })
    }

    async fn floating_ip_status(
        &self,
        input: FloatingIpStatusInput,
    ) -> Result<FloatingIpStatusOutput> {
        let state = self.current_assignment(&input.ip_id).await?;
        Ok(FloatingIpStatusOutput {
            zone: state.zone,
            attached_to: state.attached_to,
        })
    }
}

/// The `EnvoyAdapter::dispatch` body every `floating_ip.*` adapter shares.
///
/// Takes the provider by `&dyn` so the three impls below are a delegation each
/// rather than a copy each; the unsupported-verb refusal names the provider
/// from its own [`FloatingIpProvider::id`], so it stays correct for a fourth
/// vendor without anybody remembering to edit a string literal.
pub async fn dispatch_floating_ip_verb(
    provider: &dyn FloatingIpProvider,
    verb_id: &str,
    input: Value,
) -> Result<Value> {
    match verb_id {
        id if id == FloatingIpAssign::ID => {
            let args: FloatingIpAssignInput =
                serde_json::from_value(input).with_context(|| format!("{id}: decode input"))?;
            let out = provider.floating_ip_assign(args).await?;
            Ok(serde_json::to_value(out)?)
        }
        id if id == FloatingIpStatus::ID => {
            let args: FloatingIpStatusInput =
                serde_json::from_value(input).with_context(|| format!("{id}: decode input"))?;
            let out = provider.floating_ip_status(args).await?;
            Ok(serde_json::to_value(out)?)
        }
        other => bail!(
            "{} floating-ip envoy does not support verb {other:?}",
            provider.id()
        ),
    }
}

/// The two verbs every `floating_ip.*` adapter claims. One list, so a third
/// verb cannot land on two of the three adapters.
const FLOATING_IP_VERBS: [&str; 2] = [FloatingIpAssign::ID, FloatingIpStatus::ID];

#[async_trait]
impl EnvoyAdapter for HetznerFloatingIp {
    fn id(&self) -> &str {
        FloatingIpProvider::id(self)
    }
    fn tier(&self) -> Tier {
        Tier::S
    }
    fn flavor(&self) -> AdapterFlavor {
        AdapterFlavor::Native
    }
    fn supported_verb_ids(&self) -> Vec<&'static str> {
        FLOATING_IP_VERBS.to_vec()
    }
    async fn dispatch(&self, verb_id: &str, input: Value) -> Result<Value> {
        dispatch_floating_ip_verb(self, verb_id, input).await
    }
}

#[async_trait]
impl EnvoyAdapter for OvhFloatingIp {
    fn id(&self) -> &str {
        FloatingIpProvider::id(self)
    }
    /// `A`, not `S`, and deliberately: the adapter's OVH auth is a placeholder
    /// (bare `X-Ovh-Consumer` header, not OVH's timestamped HMAC), so the verb
    /// is dispatchable but not live-ready. See `floating_ip_adapters::ovh`.
    fn tier(&self) -> Tier {
        Tier::A
    }
    fn flavor(&self) -> AdapterFlavor {
        AdapterFlavor::Native
    }
    fn supported_verb_ids(&self) -> Vec<&'static str> {
        FLOATING_IP_VERBS.to_vec()
    }
    async fn dispatch(&self, verb_id: &str, input: Value) -> Result<Value> {
        dispatch_floating_ip_verb(self, verb_id, input).await
    }
}

#[async_trait]
impl EnvoyAdapter for VultrFloatingIp {
    fn id(&self) -> &str {
        FloatingIpProvider::id(self)
    }
    fn tier(&self) -> Tier {
        Tier::S
    }
    fn flavor(&self) -> AdapterFlavor {
        AdapterFlavor::Native
    }
    fn supported_verb_ids(&self) -> Vec<&'static str> {
        FLOATING_IP_VERBS.to_vec()
    }
    async fn dispatch(&self, verb_id: &str, input: Value) -> Result<Value> {
        dispatch_floating_ip_verb(self, verb_id, input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each adapter's envoy id must equal its provider id, or
    /// `floating_ip_provider_for` and `default_adapters()` disagree about which
    /// box a verb reaches — and the disagreement is invisible until a failover.
    #[test]
    fn the_envoy_id_is_the_provider_id_for_every_adapter() {
        let cases: [(&dyn EnvoyAdapter, &str); 3] = [
            (&HetznerFloatingIp::new("t"), "hetzner"),
            (&OvhFloatingIp::new("t"), "ovh"),
            (&VultrFloatingIp::new("t"), "vultr"),
        ];
        for (adapter, expected) in cases {
            assert_eq!(EnvoyAdapter::id(adapter), expected);
            assert_eq!(
                adapter.supported_verb_ids(),
                vec!["floating_ip.assign", "floating_ip.status"]
            );
        }
    }

    /// The shared dispatch refuses an unknown verb by naming the provider it
    /// was asked of — the three per-vendor copies this replaced each hardcoded
    /// that name, which is the drift the collapse removes.
    #[tokio::test]
    async fn an_unknown_verb_is_refused_and_names_the_provider() {
        let err = dispatch_floating_ip_verb(
            &VultrFloatingIp::new("t"),
            "floating_ip.detach",
            serde_json::json!({}),
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("vultr"), "{msg}");
        assert!(msg.contains("floating_ip.detach"), "{msg}");
    }
}
