//! Inlined-deployment constructor (W199 shape 1).
//!
//! The caller embeds Kamaji in its own process tree and holds an
//! `Arc<dyn Kamaji>`. This module owns the builder side: probe backends
//! at init, pick the first available one in a caller-supplied preference
//! order, hand back a trait object.
//!
//! For the sibling shape — separate process supervised by the host's PID 1 —
//! see [`crate::sibling`].
//!
//! ## Backend selection
//!
//! W199 §Backend availability says callers can express a preference (desktop
//! prefers Docker, fleet hosts prefer Containerd). [`Inlined::pick`] walks
//! the preference list in order and returns the first available backend.
//! Backends that the host doesn't support surface a structured
//! [`crate::BackendUnavailable`] error carrying the install hint — never a
//! panic.
//!
//! ## What this is NOT
//!
//! This is the **builder**, not a multi-backend dispatcher. The returned
//! `Arc<dyn Kamaji>` is one concrete backend. Per-WorkloadSpec routing
//! across multiple backends (the W199 §"Kamaji picks the backend"
//! vision) is downstream work and is intentionally not modeled here.

use std::sync::Arc;

use crate::probe::BackendAvailability;
use crate::{Backend, BackendUnavailable, Kamaji};

/// Pick an inlined Kamaji backend from a caller-supplied preference list.
///
/// `prefer` is walked in order; the first backend whose probe came back
/// available is selected, the matching factory is invoked, and the resulting
/// trait object is returned. If none of the preferred backends are
/// available, the function returns the probe error for the **last** entry
/// in the preference list (its install hint is what the caller most wanted).
///
/// ## Example shape
///
/// ```ignore
/// let availability = BackendAvailability::probe().await;
/// let kamaji = Inlined::pick(
///     &availability,
///     &[Backend::Docker, Backend::Containerd],
///     |backend| match backend {
///         Backend::Docker => Ok(Arc::new(docker::DockerRuntime::new()) as Arc<dyn Kamaji>),
///         Backend::Containerd => Ok(Arc::new(containerd::ContainerdRuntime::connect_at(socket).await?) as _),
///         Backend::Native => unreachable!("not in preference list"),
///     },
/// )?;
/// ```
///
/// The factory closure is invoked **only** for the selected backend, so
/// callers can construct backends that themselves require I/O without
/// paying for the ones they don't pick.
pub struct Inlined;

impl Inlined {
    /// Walk `prefer` in order and return the first available backend.
    ///
    /// The factory is invoked exactly once with the chosen backend tag.
    /// Returns `BackendUnavailable` for the *last* preferred backend if
    /// none are available (callers who prefer Docker but accept Containerd
    /// see the Docker install hint).
    pub fn pick<F>(
        availability: &BackendAvailability,
        prefer: &[Backend],
        factory: F,
    ) -> Result<Arc<dyn Kamaji>, BackendUnavailable>
    where
        F: FnOnce(Backend) -> Arc<dyn Kamaji>,
    {
        assert!(!prefer.is_empty(), "Inlined::pick: preference list cannot be empty");
        for backend in prefer {
            if availability.get(*backend).available {
                return Ok(factory(*backend));
            }
        }
        // None available — return the unavailability for the last (lowest
        // priority) entry so callers who chained "Docker, else Containerd"
        // get the Containerd install hint when both are missing.
        let last = *prefer.last().expect("len > 0 checked above");
        Err(availability.require(last).err().unwrap_or_else(|| {
            BackendUnavailable {
                backend: last,
                detail: "backend marked available but require() returned Ok".into(),
                install_hint: None,
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::BackendProbe;
    use crate::{
        DeployResult, LogOpts, LogStream, MeshAssignment, MeshIdent, RuntimeHealth, WorkloadSpec,
        WorkloadState,
    };
    use async_trait::async_trait;
    use std::path::PathBuf;

    struct StubBackend(Backend);

    #[async_trait]
    impl Kamaji for StubBackend {
        fn backend(&self) -> Backend {
            self.0
        }
        async fn deploy_workload(
            &self,
            _: &WorkloadSpec,
            _: &MeshAssignment,
        ) -> anyhow::Result<DeployResult> {
            unimplemented!()
        }
        async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadState>> {
            Ok(vec![])
        }
        async fn get_workload(&self, _: &MeshIdent) -> anyhow::Result<Option<WorkloadState>> {
            Ok(None)
        }
        async fn stream_logs(&self, _: &MeshIdent, _: LogOpts) -> anyhow::Result<LogStream> {
            unimplemented!()
        }
        async fn restart_workload(&self, _: &MeshIdent) -> anyhow::Result<()> {
            Ok(())
        }
        async fn teardown_workload(&self, _: &MeshIdent) -> anyhow::Result<()> {
            Ok(())
        }
        async fn health(&self) -> anyhow::Result<RuntimeHealth> {
            unimplemented!()
        }
    }

    fn probe(backend: Backend, available: bool) -> BackendProbe {
        BackendProbe {
            backend,
            available,
            socket_path: if available { Some(PathBuf::from("/x")) } else { None },
            detail: "test".into(),
            install_hint: if available { None } else { Some(format!("install {backend:?}")) },
        }
    }

    fn availability(native: bool, containerd: bool, docker: bool) -> BackendAvailability {
        BackendAvailability {
            native: probe(Backend::Native, native),
            containerd: probe(Backend::Containerd, containerd),
            docker: probe(Backend::Docker, docker),
        }
    }

    #[test]
    fn pick_first_available_in_preference_order() {
        let avail = availability(true, true, true);
        let result = Inlined::pick(&avail, &[Backend::Docker, Backend::Containerd], |b| {
            Arc::new(StubBackend(b)) as Arc<dyn Kamaji>
        })
        .unwrap();
        assert_eq!(result.backend(), Backend::Docker);
    }

    #[test]
    fn pick_skips_unavailable_to_next_preference() {
        let avail = availability(true, true, false);
        let result = Inlined::pick(&avail, &[Backend::Docker, Backend::Containerd], |b| {
            Arc::new(StubBackend(b)) as Arc<dyn Kamaji>
        })
        .unwrap();
        assert_eq!(result.backend(), Backend::Containerd);
    }

    #[test]
    fn pick_none_available_returns_last_preference_hint() {
        let avail = availability(false, false, false);
        let result = Inlined::pick(&avail, &[Backend::Docker, Backend::Containerd], |_| {
            unreachable!()
        });
        let err = match result {
            Ok(_) => panic!("expected BackendUnavailable"),
            Err(e) => e,
        };
        assert_eq!(err.backend, Backend::Containerd);
        assert!(err.install_hint.is_some());
    }

    #[test]
    fn factory_invoked_only_for_chosen_backend() {
        let avail = availability(true, false, true);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result = Inlined::pick(&avail, &[Backend::Containerd, Backend::Docker], |b| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Arc::new(StubBackend(b)) as Arc<dyn Kamaji>
        })
        .unwrap();
        assert_eq!(result.backend(), Backend::Docker);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    #[should_panic(expected = "preference list cannot be empty")]
    fn empty_preference_list_panics() {
        let avail = availability(true, true, true);
        let _ = Inlined::pick(&avail, &[], |_| unreachable!());
    }
}
