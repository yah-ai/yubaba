//! The three vendor floating/reserved-IP HTTP adapters (R594-F5, R859-F3).
//!
//! [`HetznerFloatingIp`], [`OvhFloatingIp`] and [`VultrFloatingIp`] each
//! implement [`floating_ip::FloatingIpProvider`] — resolve a machine to a
//! provider-native attach id, read where the IP lives now, and move it. The
//! idempotency and zone checks are *not* here; they are
//! [`floating_ip::reconcile_assignment`], written once above these three.
//!
//! # Why this is its own crate
//!
//! It was `cloud::provider::{hetzner,ovh,vultr}_floating_ip` until 2026-09-08.
//! R859-F2 extracted the seam into `yah-floating-ip` so `yubaba` could plan a
//! failover, but left the adapters behind — which meant the fleet daemon could
//! *decide* to move an IP and had no way to move it, and
//! `ingress_effector::apply_effect`'s `Reassign` arm returned a `NotApplied`
//! naming its own missing transport. R859-F3 is that transport.
//!
//! Three crates, three jobs, and the split is load-bearing in both directions:
//!
//! - `yah-floating-ip` — the seam, the shared reconcile core, the pure planner.
//!   Two dependencies (`anyhow`, `async-trait`) and no more, forever: it links
//!   into the fleet daemon, so a `reqwest` in its manifest ships a TLS stack to
//!   every node. **Do not solve an adapter problem by adding a dep there.**
//! - **this crate** — a reqwest client per vendor and the wire types it
//!   decodes. Owned by neither consumer, which is exactly what lets `cloud` and
//!   `yubaba` both link it without either depending on the other.
//! - `yah-cloud` — the `floating_ip.*` envoy verb layer
//!   (`cloud::provider::floating_ip_envoy`) and the credentialed constructor
//!   `floating_ip_provider_for`, which resolves vault slots through `fob`.
//!   Neither an envoy verb catalog nor a credential vault belongs on a fleet
//!   node, so neither moved.
//!
//! # The credential is an argument, not a lookup
//!
//! [`adapter_for`] takes the token; it never reads one. `cloud` resolves it
//! from `fob` (an operator laptop with a vault), `yubaba` reads it from a
//! `fob`-injected token file (a fleet node with a mounted secret) — two
//! different rails onto one constructor, and the reason this crate has no
//! opinion about where a secret comes from.
//!
//! # None of this is exercised on today's fleet
//!
//! Every machine in `.yah/infra/machines/*.toml` declares `provider =
//! "static"`, which has no adapter here, and none declares an
//! `ingress_floating_ip` — so `plan_ingress_owner_effect` cannot emit
//! `Reassign` at all. The mock suites below pin the request/response shapes and
//! the refusals; they do not and cannot pin these against a live vendor API.
//! OVH in particular is **not live-ready** — see [`ovh`]'s module doc.

use anyhow::{bail, Result};
use floating_ip::FloatingIpProvider;

pub mod hetzner;
pub mod ovh;
pub mod vultr;

pub use hetzner::HetznerFloatingIp;
pub use ovh::OvhFloatingIp;
pub use vultr::VultrFloatingIp;

/// Build the adapter for `provider`, authenticated with `credential`.
///
/// The one place a provider id becomes a client, so
/// [`FLOATING_IP_PROVIDERS`]'s rows and the constructors that serve them cannot
/// drift apart. Both callers reach it: `cloud::provider::floating_ip_provider_for`
/// after a `fob` vault lookup, and `yubaba`'s ingress effector after reading a
/// mounted token file.
///
/// `credential` is whatever that provider authenticates with — a Hetzner Cloud
/// API token, an OVH consumer key, a Vultr personal access token. Checking it
/// is the vendor's job; an empty one is refused here only because a blank
/// secret is always a configuration error and never an intent.
pub fn adapter_for(provider: &str, credential: &str) -> Result<Box<dyn FloatingIpProvider>> {
    if credential.trim().is_empty() {
        bail!("floating-ip adapter for {provider:?}: the supplied credential is empty");
    }
    Ok(match provider {
        "hetzner" => Box::new(HetznerFloatingIp::new(credential)),
        "ovh" => Box::new(OvhFloatingIp::new(credential)),
        "vultr" => Box::new(VultrFloatingIp::new(credential)),
        other => bail!(
            "provider {other:?} has no floating-IP adapter — floating/reserved IPs are \
             implemented for {} only",
            floating_ip::supported_floating_ip_providers(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use floating_ip::FLOATING_IP_PROVIDERS;

    /// The registry table and this constructor answer the same question, and a
    /// row without a constructor is a machine that validates clean and then
    /// cannot be failed over — the failure this pins is silent everywhere else.
    #[test]
    fn every_row_of_the_registry_has_a_constructor_here() {
        for (id, _, _) in FLOATING_IP_PROVIDERS {
            let built = adapter_for(id, "test-credential")
                .unwrap_or_else(|e| panic!("registry lists {id:?} but adapter_for refused: {e:#}"));
            assert_eq!(
                built.id(),
                *id,
                "the adapter built for {id:?} reports a different provider id"
            );
        }
    }

    #[test]
    fn an_unlisted_provider_is_refused_by_name_and_told_what_is_supported() {
        let msg = match adapter_for("digitalocean", "tok") {
            Ok(_) => panic!("digitalocean has no floating-IP adapter but one was built"),
            Err(e) => format!("{e:#}"),
        };
        assert!(msg.contains("digitalocean"), "{msg}");
        assert!(
            msg.contains("hetzner") && msg.contains("ovh") && msg.contains("vultr"),
            "the refusal should name what IS supported: {msg}"
        );
    }

    /// An empty token reaches the vendor as a 401 at the worst possible moment
    /// — mid-failover — so it is refused at construction instead.
    #[test]
    fn a_blank_credential_is_refused_before_any_client_is_built() {
        assert!(adapter_for("hetzner", "   ").is_err());
    }
}
