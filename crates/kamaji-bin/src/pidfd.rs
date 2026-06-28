//! Pidfd-based child reaper (R406-T6).
//!
//! Linux's `pidfd_open(2)` gives Kamaji a stable, race-free handle to a
//! child process. Two payoffs over plain SIGCHLD-driven supervision:
//!
//! 1. **No pid-reuse races.** A pidfd refers to one specific process; once
//!    that process exits and is reaped, further operations on the pidfd return
//!    `ESRCH` instead of silently targeting a recycled pid.
//! 2. **Tokio integration is trivial.** The pidfd becomes readable when the
//!    child exits — exactly what `epoll(7)` (and therefore `tokio::io::unix::AsyncFd`)
//!    fires on. No `signalfd`, no per-process `SIGCHLD` plumbing.
//!
//! The reaper:
//!
//! - [`pidfd_open`] wraps the raw syscall (Linux-only; non-Linux returns
//!   [`PidfdError::Unsupported`]).
//! - [`PidfdReaper::register`] spawns a per-pidfd tokio task that awaits
//!   readability, calls `waitid(P_PIDFD, …, WEXITED)` via nix, and forwards
//!   a [`ExitEvent`] over an unbounded mpsc channel.
//! - [`PidfdReaper::recv`] is the consumer side — Kamaji's server reads
//!   events here and pushes them to Yubaba as
//!   [`constable_proto::ConstableToWarden::WorkloadExited`].
//!
//! The translation from `WaitStatus` to the wire [`constable_proto::ExitStatus`]
//! is in [`translate_wait_status`] and is the only piece tested off-Linux.

use std::io;
use std::os::fd::OwnedFd;

use kamaji_proto::{ExitStatus as WireExitStatus, WorkloadId};
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct ExitEvent {
    pub workload_id: WorkloadId,
    pub status: WireExitStatus,
}

#[derive(Debug, Error)]
pub enum PidfdError {
    #[error("pidfd_open({pid}) failed: {source}")]
    Open {
        pid: u32,
        #[source]
        source: io::Error,
    },
    #[error("pidfd async-register failed: {0}")]
    AsyncRegister(#[source] io::Error),
    #[error("waitid(P_PIDFD) failed: {0}")]
    Wait(#[source] io::Error),
    #[error("pidfd reaping requires Linux")]
    Unsupported,
}

/// Linux: invoke the `pidfd_open` syscall and return the resulting pidfd.
///
/// `flags` is always 0 — `PIDFD_NONBLOCK` is not needed because tokio's
/// `AsyncFd` registers the fd with epoll and never issues a blocking read on
/// it. Non-Linux: returns [`PidfdError::Unsupported`].
pub fn pidfd_open(pid: u32) -> Result<OwnedFd, PidfdError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if raw < 0 {
            return Err(PidfdError::Open {
                pid,
                source: io::Error::last_os_error(),
            });
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err(PidfdError::Unsupported)
    }
}

/// Reaper for native workloads. Each registered pidfd is supervised by its
/// own tokio task; results land on the reaper's `events` channel as soon as
/// the kernel marks the pidfd readable.
pub struct PidfdReaper {
    events_tx: mpsc::UnboundedSender<ExitEvent>,
    events_rx: mpsc::UnboundedReceiver<ExitEvent>,
}

impl PidfdReaper {
    pub fn new() -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            events_tx,
            events_rx,
        }
    }

    /// Get a cloneable handle that can register pidfds with this reaper from
    /// any task without parking the reaper itself.
    pub fn handle(&self) -> PidfdReaperHandle {
        PidfdReaperHandle {
            events_tx: self.events_tx.clone(),
        }
    }

    /// Pull the next exit event. Returns `None` once every handle has been
    /// dropped *and* every spawned watcher has finished.
    pub async fn recv(&mut self) -> Option<ExitEvent> {
        self.events_rx.recv().await
    }
}

impl Default for PidfdReaper {
    fn default() -> Self {
        Self::new()
    }
}

/// Cloneable submitter for [`PidfdReaper`]. Holding one keeps the channel
/// alive even after the reaper is moved into a recv loop.
#[derive(Clone)]
pub struct PidfdReaperHandle {
    events_tx: mpsc::UnboundedSender<ExitEvent>,
}

impl PidfdReaperHandle {
    /// Spawn a watcher for `pidfd`. When the kernel marks the pidfd readable,
    /// the watcher reaps via `waitid(P_PIDFD, …, WEXITED)` and emits an
    /// [`ExitEvent`] on the reaper's channel.
    ///
    /// Linux-only. Non-Linux returns [`PidfdError::Unsupported`] without
    /// spawning anything.
    pub fn register(
        &self,
        workload_id: WorkloadId,
        pidfd: OwnedFd,
    ) -> Result<(), PidfdError> {
        #[cfg(target_os = "linux")]
        {
            let tx = self.events_tx.clone();
            let watcher = linux::watch_pidfd(pidfd)?;
            tokio::spawn(async move {
                match watcher.await {
                    Ok(status) => {
                        let _ = tx.send(ExitEvent {
                            workload_id,
                            status,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            workload = %workload_id.as_str(),
                            error = %e,
                            "pidfd watcher failed; workload exit will not surface as a wire event",
                        );
                    }
                }
            });
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (workload_id, pidfd);
            Err(PidfdError::Unsupported)
        }
    }
}

/// Translate `nix::sys::wait::WaitStatus` into the wire-level
/// [`WireExitStatus`]. Exposed for unit testing on every platform.
#[cfg(target_os = "linux")]
pub fn translate_wait_status(
    s: nix::sys::wait::WaitStatus,
) -> Result<WireExitStatus, PidfdError> {
    use nix::sys::wait::WaitStatus;
    match s {
        WaitStatus::Exited(_, code) => Ok(WireExitStatus::Exited(code)),
        WaitStatus::Signaled(_, signal, _core_dumped) => {
            Ok(WireExitStatus::Signaled(signal as i32))
        }
        // Stopped / Continued / StillAlive shouldn't reach us — we wait with
        // WEXITED only. If the kernel ever surfaces one of these anyway, treat
        // it as an internal error so the caller can surface it.
        other => Err(PidfdError::Wait(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected WaitStatus from waitid(P_PIDFD): {other:?}"),
        ))),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::future::Future;
    use std::io;
    use std::os::fd::{AsFd, OwnedFd};

    use nix::sys::wait::{waitid, Id, WaitPidFlag};
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;

    use super::{translate_wait_status, PidfdError, WireExitStatus};

    /// Wrap `pidfd` in an `AsyncFd` and return a future that yields the wire
    /// `ExitStatus` once the kernel marks the pidfd readable (= child exited).
    pub(super) fn watch_pidfd(
        pidfd: OwnedFd,
    ) -> Result<impl Future<Output = Result<WireExitStatus, PidfdError>>, PidfdError> {
        let async_fd = AsyncFd::with_interest(pidfd, Interest::READABLE)
            .map_err(PidfdError::AsyncRegister)?;
        Ok(async move {
            // Wait for EPOLLIN — kernel fires this on child exit.
            let _guard = async_fd
                .readable()
                .await
                .map_err(PidfdError::AsyncRegister)?;
            let pidfd = async_fd.into_inner();
            reap_now(&pidfd)
        })
    }

    fn reap_now(pidfd: &OwnedFd) -> Result<WireExitStatus, PidfdError> {
        let status = waitid(Id::PIDFd(pidfd.as_fd()), WaitPidFlag::WEXITED)
            .map_err(|e| PidfdError::Wait(io::Error::from_raw_os_error(e as i32)))?;
        translate_wait_status(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn pidfd_open_off_linux_returns_unsupported() {
        let err = pidfd_open(1).unwrap_err();
        assert!(matches!(err, PidfdError::Unsupported));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn translate_exited_to_wire() {
        use nix::sys::wait::WaitStatus;
        use nix::unistd::Pid;
        let s = WaitStatus::Exited(Pid::from_raw(1234), 0);
        assert_eq!(translate_wait_status(s).unwrap(), WireExitStatus::Exited(0));
        let s = WaitStatus::Exited(Pid::from_raw(1234), 7);
        assert_eq!(translate_wait_status(s).unwrap(), WireExitStatus::Exited(7));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn translate_signaled_to_wire() {
        use nix::sys::signal::Signal;
        use nix::sys::wait::WaitStatus;
        use nix::unistd::Pid;
        let s = WaitStatus::Signaled(Pid::from_raw(1234), Signal::SIGKILL, false);
        assert_eq!(
            translate_wait_status(s).unwrap(),
            WireExitStatus::Signaled(Signal::SIGKILL as i32)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn translate_unexpected_status_is_error() {
        use nix::sys::wait::WaitStatus;
        let s = WaitStatus::StillAlive;
        assert!(matches!(translate_wait_status(s), Err(PidfdError::Wait(_))));
    }

    /// End-to-end on Linux: spawn `/bin/true`, hand its pidfd to the reaper,
    /// expect an `Exited(0)` event back. Ignored on non-Linux automatically
    /// because the whole test module is `#[cfg(target_os = "linux")]`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reaper_emits_exited_for_real_child() {
        use std::process::Command;
        use std::time::Duration;

        let mut reaper = PidfdReaper::new();
        let handle = reaper.handle();

        let child = Command::new("/bin/true")
            .spawn()
            .expect("/bin/true should be available on Linux");
        let pid = child.id();
        // Drop the std handle so it doesn't reap on Drop — the pidfd takes
        // ownership of the reap path.
        std::mem::forget(child);

        let pidfd = pidfd_open(pid).expect("pidfd_open");
        handle
            .register(WorkloadId::new("test-child"), pidfd)
            .expect("register");

        let event = tokio::time::timeout(Duration::from_secs(5), reaper.recv())
            .await
            .expect("reaper recv timeout")
            .expect("reaper closed without event");

        assert_eq!(event.workload_id.as_str(), "test-child");
        assert_eq!(event.status, WireExitStatus::Exited(0));
    }
}
