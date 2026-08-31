//! Drive `yubaba-tenant-streamer`'s tail loop against a raft state machine
//! held in this process — R732-T4/T5.
//!
//! In production the streamer is a separate kamaji-managed service that pulls
//! its fencing token over HTTP (`GET /tenants/{id}`), and it deliberately does
//! not link the yubaba crate: hosting the data plane's byte mover inside the
//! control-plane process is what W253 tenet 1 forbids.
//!
//! That decoupling is exactly what makes it testable. The loop only ever sees
//! an [`OwnershipSource`], so a test can hand it a state machine — or two, one
//! per side of a partition — instead of a listener. R732-T5's split-brain test
//! needs a partitioned master that is *alive and still writing*, which is the
//! only interesting case for fencing; standing up HTTP servers to express that
//! would mean testing the servers.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use workload_spec::TenantId;
use yubaba::raft::{apply, YubabaNodeId, YubabaRequest, YubabaResponse, YubabaState};
use yubaba_tenant_streamer::ownership::{LeaseRenewal, Ownership, OwnershipSource};

/// An [`OwnershipSource`] backed by a [`YubabaState`] this test owns outright.
///
/// Reads go straight to the state — the same *local* read the HTTP endpoint
/// serves, with the same staleness semantics. Renewals go through the real
/// [`apply`], so a renewal is CAS-checked by production code rather than by
/// the harness's idea of what a renewal means.
///
/// **The clock is explicit.** Lease arithmetic is the one place where a
/// wall-clock read would make a fencing test lie: R732-T5's first draft passed
/// for the wrong reason precisely because a lease had quietly expired by the
/// time the assertion ran, so the timeout did the fencing and the epoch was
/// never exercised. [`set_now`](Self::set_now) makes that a thing a test
/// states rather than something it inherits.
pub struct LocalOwnership {
    state: Arc<Mutex<YubabaState>>,
    node: YubabaNodeId,
    now: Mutex<u64>,
}

impl LocalOwnership {
    pub fn new(state: Arc<Mutex<YubabaState>>, node: YubabaNodeId, now: u64) -> Self {
        Self {
            state,
            node,
            now: Mutex::new(now),
        }
    }

    /// Advance (or rewind) this source's notion of now.
    pub fn set_now(&self, now: u64) {
        *self.now.lock().unwrap() = now;
    }

    pub fn now(&self) -> u64 {
        *self.now.lock().unwrap()
    }

    /// The state this source reads, so a test can partition it by simply not
    /// applying entries to one side.
    pub fn state(&self) -> Arc<Mutex<YubabaState>> {
        self.state.clone()
    }
}

#[async_trait]
impl OwnershipSource for LocalOwnership {
    async fn ownership(&self, tenant: &TenantId) -> Result<Ownership> {
        let now = self.now();
        let state = self.state.lock().unwrap();
        Ok(Ownership {
            fencing_token: state.tenant_fencing_token(tenant, self.node, now),
            lease_expires: state
                .tenants
                .get(tenant)
                .map(|r| r.lease_expires)
                .unwrap_or(0),
            now,
        })
    }

    async fn renew_lease(
        &self,
        tenant: &TenantId,
        epoch: u64,
        lease_secs: u64,
    ) -> Result<LeaseRenewal> {
        let now = self.now();
        let mut state = self.state.lock().unwrap();
        let resp = apply(
            &mut state,
            &YubabaRequest::RenewTenantLease {
                tenant: tenant.clone(),
                node: self.node,
                epoch,
                lease_secs,
                now,
            },
        );
        Ok(match resp {
            YubabaResponse::Tenant(outcome) => match outcome {
                yubaba::raft::TenantOutcome::Granted { epoch } => LeaseRenewal::Renewed { epoch },
                yubaba::raft::TenantOutcome::Fenced {
                    current_epoch,
                    current_owner,
                } => LeaseRenewal::Fenced {
                    current_epoch,
                    current_owner,
                },
            },
            other => anyhow::bail!("RenewTenantLease answered with {other:?}"),
        })
    }
}
