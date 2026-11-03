//! The serving fence (W363 §3): one claim for the whole server, acquired at
//! start, asserted on every push and every [`FENCE_PERIOD`].
//!
//! Fence loss is terminal for this process: the listener closes and the
//! process exits 0, so `restart_policy = on-failure` does not restart it and
//! re-acquire (which would displace the legitimate owner and ping-pong).

use anyhow::{bail, Result};
use std::sync::Arc;
use std::time::Duration;
use store_claim::claim::{acquire, assert_holds, ClaimLost, ClaimOutcome};
use store_claim::{probe_conditional_puts, BackupTarget, PreconditionSupport};
use tokio::sync::watch;

pub const FENCE_PERIOD: Duration = Duration::from_secs(30);

pub struct Fence {
    target: BackupTarget,
    epoch: u64,
    lost: watch::Sender<Option<String>>,
}

/// What one [`Fence::check`] found.
#[derive(Debug)]
pub enum FenceCheck {
    Holds,
    /// Definitive: someone else holds the claim. The fence is now lost.
    Lost(ClaimLost),
    /// The store could not be read. A push must be refused (an unreachable
    /// store is indistinguishable from a partition), but this alone does not
    /// end the process: a transient R2 error that exited 0 would leave the
    /// single replica stopped under `restart_policy = on-failure`.
    Unknown(anyhow::Error),
}

impl Fence {
    /// W363 §4 startup steps 1–2: refuse a store that ignores conditional
    /// puts, then take the claim.
    pub async fn establish(target: BackupTarget, owner: &str) -> Result<Arc<Self>> {
        match probe_conditional_puts(&target).await? {
            PreconditionSupport::Honoured => {}
            PreconditionSupport::Degraded { stage } => bail!(
                "the claim store does not enforce conditional puts (failed at {}); \
                 refusing to start, since the fence would be last-write-wins",
                stage.as_str()
            ),
        }
        let epoch = match acquire(&target, owner).await? {
            ClaimOutcome::Granted { claim, previous } => {
                tracing::info!(
                    epoch = claim.epoch,
                    previous = ?previous.map(|p| (p.epoch, p.owner)),
                    "acquired the fleet-git writer claim"
                );
                claim.epoch
            }
            ClaimOutcome::Lost { current } => bail!(
                "lost the claim race to {} (epoch {}): another instance is starting right now",
                current.owner,
                current.epoch
            ),
        };
        let (lost, _) = watch::channel(None);
        Ok(Arc::new(Self { target, epoch, lost }))
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_lost(&self) -> bool {
        self.lost.borrow().is_some()
    }

    /// Resolves once the fence is lost, with the reason.
    pub async fn wait_lost(&self) -> String {
        let mut rx = self.lost.subscribe();
        loop {
            if let Some(why) = rx.borrow_and_update().clone() {
                return why;
            }
            if rx.changed().await.is_err() {
                return "fence dropped".into();
            }
        }
    }

    /// Enter fence loss for a reason found outside the claim, i.e. the journal
    /// fork fence (W363 §2 step 4: another writer appended our `seq`).
    pub fn lose(&self, why: String) {
        tracing::warn!(%why, "fleet-git fence lost; closing the listener");
        self.lost.send_if_modified(|cur| {
            if cur.is_some() {
                return false;
            }
            *cur = Some(why);
            true
        });
    }

    pub async fn check(&self) -> FenceCheck {
        if let Some(why) = self.lost.borrow().clone() {
            return FenceCheck::Unknown(anyhow::anyhow!("fence already lost: {why}"));
        }
        match assert_holds(&self.target, self.epoch).await {
            Ok(Ok(())) => FenceCheck::Holds,
            Ok(Err(lost)) => {
                tracing::warn!(%lost, "fleet-git writer claim lost; closing the listener");
                self.lost.send_replace(Some(lost.to_string()));
                FenceCheck::Lost(lost)
            }
            Err(e) => FenceCheck::Unknown(e),
        }
    }

    /// The 30 s timer, so a displaced instance stops serving stale refs to
    /// fetchers instead of noticing only on its next push.
    pub fn spawn_timer(self: &Arc<Self>, period: Duration) -> tokio::task::JoinHandle<()> {
        let fence = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await;
            loop {
                tick.tick().await;
                match fence.check().await {
                    FenceCheck::Holds => {}
                    FenceCheck::Lost(_) => return,
                    FenceCheck::Unknown(e) => {
                        if fence.is_lost() {
                            return;
                        }
                        tracing::warn!(error = %e, "could not read the claim; will retry");
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    #[tokio::test]
    async fn second_acquire_fences_the_first() {
        let store: Arc<dyn object_store::ObjectStore> = Arc::new(InMemory::new());
        let t = |s: &Arc<dyn object_store::ObjectStore>| BackupTarget { store: s.clone(), prefix: String::new() };
        let a = Fence::establish(t(&store), "fleet-git@a").await.unwrap();
        assert!(matches!(a.check().await, FenceCheck::Holds));
        let b = Fence::establish(t(&store), "fleet-git@b").await.unwrap();
        assert!(b.epoch() > a.epoch());
        assert!(matches!(a.check().await, FenceCheck::Lost(ClaimLost::Superseded { .. })));
        assert!(a.is_lost());
        assert!(a.wait_lost().await.contains("superseded"));
        assert!(matches!(b.check().await, FenceCheck::Holds));
    }
}
