//! Constable's native workload spawn surface (R406-T5).
//!
//! Pipeline for a native workload:
//!
//! 1. Warden → Constable `Deploy(WorkloadSpec)` over the UDS.
//! 2. Constable creates a per-workload cgroup via [`crate::CgroupV2`] (R406-T4).
//! 3. Constable calls [`spawn`] (this module) — `fork`, parent attaches the
//!    child to the cgroup, signals it via a sync pipe, child drops privileges
//!    (`setresuid/setresgid`, capability bset clear, `landlock_restrict_self`),
//!    then `execvpe` into the workload binary.
//! 4. Parent returns a [`NativeChild`] holding the child's pid; R406-T6
//!    wires the pidfd loop on top.
//!
//! ## WorkloadSpec interpretation
//!
//! The native driver consumes the same [`WorkloadSpec`] shape that container
//! workloads use. Decisions intentionally narrowed for native:
//!
//! - **`user`** is supported in two numeric forms: `"<uid>"` or `"<uid>:<gid>"`.
//!   Username lookup (`"appuser"`) is rejected with [`SpawnError::InvalidSpec`]
//!   — musl-static binaries can't resolve nsswitch reliably, and Constable
//!   intentionally does not link nss plugins. `None` means "stay at Constable's
//!   current uid", which in production is normally root.
//! - **`command` / `entrypoint`** follow OCI semantics: `entrypoint` prepends
//!   `command`; the combined `argv` must be non-empty.
//! - **`env`** carries only [`EnvValue::Literal`] entries. `FromSecret` /
//!   `FromMesh` references are Warden's responsibility to resolve before the
//!   spec reaches Constable; unresolved variants are rejected.
//! - **`volumes`** translate to a landlock allow-list (read-only fs base
//!   everywhere, RW or RO at each volume `target` per `read_only`). Only
//!   `Bind` sources are honored — `Named` and `Tmpfs` need separate mount
//!   choreography and are deferred.
//! - **Capabilities** default to "drop everything". Workloads that need a
//!   specific capability (e.g. `CAP_NET_BIND_SERVICE` to bind ports < 1024)
//!   will get an explicit field added later.
//! - **`workdir`** is `chdir`'d in the child before exec.
//!
//! ## Tested vs. live
//!
//! [`SandboxPlan::from_spec`] and its helpers are pure data and exhaustively
//! unit-tested on every platform. The actual fork+exec+sandbox path lives in
//! the Linux-only [`spawn`] entry point — it requires a real cgroup hierarchy
//! and root (or matching capabilities) and is exercised only on cloud-tier
//! Linux runners. Non-Linux callers receive [`SpawnError::Unsupported`].

use std::collections::HashMap;
use std::path::PathBuf;

use thiserror::Error;
use workload_spec::{EnvValue, ResourceLimits, VolumeMount, VolumeSource, WorkloadSpec};

use crate::cgroup::CgroupHandle;

/// Sanitised workload payload ready to hand to the Linux fork+exec path.
///
/// Every field is concrete: no symbolic references, no username lookups, no
/// undecided defaults. Constructing one validates the spec; mis-shaped specs
/// surface as [`SpawnError::InvalidSpec`] *before* we fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    /// argv[0..] passed to `execvpe`. Guaranteed non-empty.
    pub argv: Vec<String>,
    /// `chdir` target inside the child, before exec. `None` leaves it at `/`.
    pub workdir: Option<PathBuf>,
    /// Resolved literal env vars. Stable order (the spec's order).
    pub env: Vec<(String, String)>,
    /// uid/gid drop target. `None` keeps Constable's current uid.
    pub user: Option<UserGroup>,
    /// Landlock allow-list derived from `volumes`.
    pub landlock: LandlockPolicy,
    /// Resource caps copied through verbatim (cgroup module owns the writes).
    pub resources: ResourceLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserGroup {
    pub uid: u32,
    pub gid: u32,
}

/// Landlock policy: a read-only filesystem base plus explicit allow rules.
///
/// Constable always installs a ruleset that defaults to denying writes
/// everywhere; the entries below grant the listed access at the given path.
/// Reads from `/` are permitted by default (so dynamic linker + shared libs
/// resolve) — this is a balance between strict isolation and "workloads have
/// to actually run". Tighter read restrictions land in a follow-up once we
/// know what workloads actually need.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LandlockPolicy {
    pub rules: Vec<LandlockRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockRule {
    pub path: PathBuf,
    pub access: LandlockAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockAccess {
    Read,
    ReadWrite,
}

/// Handle to a spawned native workload.
///
/// - `pid` — OS pid.
/// - `pidfd` — race-free Linux handle opened by [`spawn`] right after `fork`;
///   the [`crate::pidfd::PidfdReaper`] consumes it to await the child's exit.
/// - `stdout` / `stderr` — read ends of the pipes Constable retains; the
///   child's fd 1 and fd 2 are dup'd from the write ends. The deploy path
///   (R406-T8) hands these to [`crate::journal::forward_reader`] to fan log
///   lines into journald (R406-T10).
///
/// All three fd fields are `None` off-Linux because [`spawn`] returns
/// [`SpawnError::Unsupported`] without constructing a `NativeChild`.
#[derive(Debug)]
pub struct NativeChild {
    pub pid: u32,
    pub pidfd: Option<std::os::fd::OwnedFd>,
    pub stdout: Option<std::os::fd::OwnedFd>,
    pub stderr: Option<std::os::fd::OwnedFd>,
}

#[derive(Debug, Error)]
pub enum SpawnError {
    #[error("invalid native workload spec: {0}")]
    InvalidSpec(String),

    #[error("native spawn requires Linux")]
    Unsupported,

    #[error("syscall {syscall} failed: {source}")]
    Syscall {
        syscall: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("landlock setup failed: {0}")]
    Landlock(String),

    #[error("capability drop failed: {0}")]
    CapDrop(String),

    #[error("cgroup attach failed: {0}")]
    Cgroup(#[from] crate::cgroup::CgroupError),
}

impl SandboxPlan {
    /// Validate and extract a [`SandboxPlan`] from a container-shaped
    /// [`WorkloadSpec`]. Pure function; no I/O.
    pub fn from_spec(spec: &WorkloadSpec) -> Result<Self, SpawnError> {
        let argv = build_argv(spec)?;
        let env = resolve_env(&spec.env)?;
        let user = match &spec.user {
            Some(s) => Some(parse_user(s)?),
            None => None,
        };
        let landlock = derive_landlock(&spec.volumes);
        Ok(SandboxPlan {
            argv,
            workdir: spec.workdir.clone(),
            env,
            user,
            landlock,
            resources: spec.resources.clone(),
        })
    }

    /// Render `env` as a `KEY=VALUE` vector suitable for `execvpe`. Duplicate
    /// names use last-write-wins (matching the OCI runtime contract).
    pub fn env_pairs(&self) -> Vec<String> {
        let mut seen: HashMap<&str, usize> = HashMap::new();
        let mut out: Vec<String> = Vec::with_capacity(self.env.len());
        for (k, v) in &self.env {
            let entry = format!("{k}={v}");
            if let Some(&idx) = seen.get(k.as_str()) {
                out[idx] = entry;
            } else {
                seen.insert(k.as_str(), out.len());
                out.push(entry);
            }
        }
        out
    }
}

fn build_argv(spec: &WorkloadSpec) -> Result<Vec<String>, SpawnError> {
    let mut argv: Vec<String> = Vec::new();
    if let Some(ep) = &spec.entrypoint {
        argv.extend(ep.iter().cloned());
    }
    if let Some(cmd) = &spec.command {
        argv.extend(cmd.iter().cloned());
    }
    if argv.is_empty() {
        return Err(SpawnError::InvalidSpec(
            "native workload must declare entrypoint or command — image defaults are not visible \
             to the native driver"
                .into(),
        ));
    }
    Ok(argv)
}

fn resolve_env(env: &[workload_spec::EnvVar]) -> Result<Vec<(String, String)>, SpawnError> {
    let mut out = Vec::with_capacity(env.len());
    for e in env {
        match &e.value {
            EnvValue::Literal { value } => out.push((e.name.clone(), value.clone())),
            EnvValue::FromSecret { .. } => {
                return Err(SpawnError::InvalidSpec(format!(
                    "env {name:?} is a FromSecret ref; Warden must resolve secret refs before \
                     dispatching to Constable",
                    name = e.name
                )));
            }
            EnvValue::FromMesh { .. } => {
                return Err(SpawnError::InvalidSpec(format!(
                    "env {name:?} is a FromMesh ref; Warden must resolve mesh refs before \
                     dispatching to Constable",
                    name = e.name
                )));
            }
        }
    }
    Ok(out)
}

fn parse_user(s: &str) -> Result<UserGroup, SpawnError> {
    let (uid_str, gid_str) = match s.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (s, None),
    };
    let uid: u32 = uid_str.parse().map_err(|_| {
        SpawnError::InvalidSpec(format!(
            "user field {s:?} must be numeric (uid or uid:gid); username lookup is not supported \
             on the native driver"
        ))
    })?;
    let gid: u32 = match gid_str {
        Some(g) => g.parse().map_err(|_| {
            SpawnError::InvalidSpec(format!(
                "user field {s:?} must be numeric — gid component is not parseable"
            ))
        })?,
        // POSIX convention: missing gid means "match uid".
        None => uid,
    };
    Ok(UserGroup { uid, gid })
}

fn derive_landlock(volumes: &[VolumeMount]) -> LandlockPolicy {
    let mut rules = Vec::new();
    for v in volumes {
        // Only Bind mounts have a host path landlock can grant access to.
        // Named volumes need warden-managed mount setup; Tmpfs needs a mount
        // syscall — both deferred to a follow-up.
        if !matches!(v.source, VolumeSource::Bind { .. }) {
            continue;
        }
        let access = if v.read_only {
            LandlockAccess::Read
        } else {
            LandlockAccess::ReadWrite
        };
        rules.push(LandlockRule {
            path: v.target.clone(),
            access,
        });
    }
    LandlockPolicy { rules }
}

/// Fork+exec the workload as configured by [`SandboxPlan`].
///
/// `cgroup` is the per-workload cgroup minted by [`crate::CgroupV2::create_workload`]
/// — the parent writes the child's pid into its `cgroup.procs` before the
/// child execs the workload binary.
///
/// Linux-only. Other platforms return [`SpawnError::Unsupported`].
pub fn spawn(plan: &SandboxPlan, cgroup: &CgroupHandle) -> Result<NativeChild, SpawnError> {
    #[cfg(target_os = "linux")]
    {
        linux::spawn(plan, cgroup)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plan, cgroup);
        Err(SpawnError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, ABI,
    };
    use nix::fcntl::OFlag;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{execvpe, fork, pipe2, setresgid, setresuid, ForkResult, Gid, Uid};

    use super::{LandlockAccess, NativeChild, SandboxPlan, SpawnError};
    use crate::cgroup::CgroupHandle;

    pub fn spawn(plan: &SandboxPlan, cgroup: &CgroupHandle) -> Result<NativeChild, SpawnError> {
        // All pipes are O_CLOEXEC: their parent-side fds get auto-closed at
        // exec so the workload binary doesn't see Constable's internal fds.
        // The child manually dup2s the stdout/stderr write ends into fd 1 / 2
        // before exec — dup2 clears CLOEXEC on the target, so fd 1 / 2 stay
        // open across exec (which is the entire point).
        //
        // Status pipe: parent reads child_read; child writes child_write on
        // pre-exec failure. CLOEXEC on child_write means a successful exec
        // closes the writer end → parent sees EOF and treats it as success.
        let cloexec = OFlag::O_CLOEXEC;
        let (parent_read, parent_write) =
            pipe2(cloexec).map_err(syscall("pipe2(parent)"))?;
        let (child_read, child_write) =
            pipe2(cloexec).map_err(syscall("pipe2(child)"))?;
        // Stdout / stderr fan-in pipes (R406-T10). Parent retains the read
        // ends inside [`NativeChild`]; the deploy path hands them to
        // [`crate::journal::forward_reader`] for line-buffered journald
        // fan-in.
        let (stdout_read, stdout_write) =
            pipe2(cloexec).map_err(syscall("pipe2(stdout)"))?;
        let (stderr_read, stderr_write) =
            pipe2(cloexec).map_err(syscall("pipe2(stderr)"))?;

        // Pre-build argv/env C strings in the parent — these allocate, so we
        // can't do them post-fork.
        let argv0 = CString::new(plan.argv[0].as_bytes())
            .map_err(|_| SpawnError::InvalidSpec("argv[0] contains a NUL".into()))?;
        let argv: Vec<CString> = plan
            .argv
            .iter()
            .map(|s| CString::new(s.as_bytes()))
            .collect::<Result<_, _>>()
            .map_err(|_| SpawnError::InvalidSpec("argv entry contains a NUL".into()))?;
        let envp: Vec<CString> = plan
            .env_pairs()
            .into_iter()
            .map(|s| CString::new(s.into_bytes()))
            .collect::<Result<_, _>>()
            .map_err(|_| SpawnError::InvalidSpec("env entry contains a NUL".into()))?;

        // SAFETY: `fork` is unsafe because the child inherits the parent's
        // address space but only one thread. We immediately do limited work
        // in the child (mostly syscalls) before exec'ing.
        let fork_res = unsafe { fork() }.map_err(syscall("fork"))?;
        match fork_res {
            ForkResult::Parent { child } => {
                drop(parent_read);
                drop(child_write);
                // Parent has no business writing to the workload's stdout /
                // stderr — keep only the read ends, which travel back in
                // [`NativeChild`] for the deploy path's forward_reader.
                drop(stdout_write);
                drop(stderr_write);

                // Attach the child to the cgroup *before* releasing the sync pipe.
                cgroup
                    .attach_pid(child.as_raw() as u32)
                    .map_err(SpawnError::from)?;

                // Wake the child.
                let mut writer = unsafe { fd_to_file(parent_write) };
                writer.write_all(&[1u8]).map_err(io_err("sync_write"))?;
                drop(writer);

                // Open the pidfd immediately — the kernel guarantees no pid
                // reuse while we still hold a process reference (we haven't
                // reaped yet), so this is race-free.
                let pidfd = crate::pidfd::pidfd_open(child.as_raw() as u32)
                    .map_err(|e| SpawnError::Syscall {
                        syscall: "pidfd_open",
                        source: std::io::Error::other(e),
                    })?;

                // Wait for the child's pre-exec status byte; 0 == "exec'd",
                // anything else means the child hit a SpawnError before exec.
                let mut reader = unsafe { fd_to_file(child_read) };
                let mut byte = [0u8; 1];
                match reader.read_exact(&mut byte) {
                    Ok(()) if byte[0] == 0 => Ok(NativeChild {
                        pid: child.as_raw() as u32,
                        pidfd: Some(pidfd),
                        stdout: Some(stdout_read),
                        stderr: Some(stderr_read),
                    }),
                    Ok(()) => {
                        // Pre-exec failed; reap the child so it doesn't zombie.
                        let _ = waitpid(child, None);
                        Err(SpawnError::Syscall {
                            syscall: pre_exec_step_label(byte[0]),
                            source: std::io::Error::from_raw_os_error(libc::EIO),
                        })
                    }
                    Err(_) => {
                        // Child died before writing its status byte — common
                        // path is "exec succeeded and the pipe was CLOEXEC'd",
                        // so empty-EOF is actually success.
                        match waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                            Ok(WaitStatus::StillAlive) | Ok(WaitStatus::Exited(_, 0)) => {
                                Ok(NativeChild {
                                    pid: child.as_raw() as u32,
                                    pidfd: Some(pidfd),
                                    stdout: Some(stdout_read),
                                    stderr: Some(stderr_read),
                                })
                            }
                            _ => Err(SpawnError::Syscall {
                                syscall: "pre_exec_eof",
                                source: std::io::Error::from_raw_os_error(libc::ESRCH),
                            }),
                        }
                    }
                }
            }
            ForkResult::Child => {
                drop(parent_write);
                drop(child_read);
                // Child has no business reading parent-bound pipe read ends.
                drop(stdout_read);
                drop(stderr_read);

                let status = pre_exec_in_child(
                    plan,
                    parent_read.as_raw_fd(),
                    child_write.as_raw_fd(),
                    stdout_write.as_raw_fd(),
                    stderr_write.as_raw_fd(),
                    &argv0,
                    &argv,
                    &envp,
                );
                // SAFETY: child path; if we land here, exec failed or we
                // declined to exec. Report a non-zero status byte and exit
                // without unwinding (the parent's destructors mustn't run).
                report_pre_exec_failure(child_write.as_raw_fd(), status);
            }
        }
    }

    /// Pre-exec sequence (runs in the forked child). Steps map to status-byte
    /// values written back to the parent on failure:
    ///
    /// | step                              | status byte |
    /// |----------------------------------- |-------------|
    /// | wait_sync                          | 1           |
    /// | dup2_stdout                        | 2           |
    /// | dup2_stderr                        | 3           |
    /// | landlock_install                   | 4           |
    /// | drop_caps                          | 5           |
    /// | setresgid                          | 6           |
    /// | setresuid                          | 7           |
    /// | chdir                              | 8           |
    /// | execvpe (unreachable on success)   | 9           |
    fn pre_exec_in_child(
        plan: &SandboxPlan,
        sync_read_fd: i32,
        status_write_fd: i32,
        stdout_write_fd: i32,
        stderr_write_fd: i32,
        argv0: &CString,
        argv: &[CString],
        envp: &[CString],
    ) -> u8 {
        let _ = status_write_fd; // surfaced via libc::write below

        // Wait for the parent to finish cgroup attach.
        let mut byte = [0u8; 1];
        let r = unsafe { libc::read(sync_read_fd, byte.as_mut_ptr() as *mut _, 1) };
        if r != 1 || byte[0] != 1 {
            return 1;
        }
        unsafe { libc::close(sync_read_fd) };

        // Redirect stdout/stderr to the pipes Constable owns. dup2 clears
        // CLOEXEC on the destination, so the workload binary keeps fd 1 / 2
        // across exec — exactly what we want. The original write-end fds
        // still have CLOEXEC and are auto-closed at exec, no manual close
        // needed.
        if unsafe { libc::dup2(stdout_write_fd, libc::STDOUT_FILENO) } < 0 {
            return 2;
        }
        if unsafe { libc::dup2(stderr_write_fd, libc::STDERR_FILENO) } < 0 {
            return 3;
        }

        if install_landlock(&plan.landlock).is_err() {
            return 4;
        }

        if drop_all_caps().is_err() {
            return 5;
        }

        if let Some(ug) = plan.user {
            let gid = Gid::from_raw(ug.gid);
            if setresgid(gid, gid, gid).is_err() {
                return 6;
            }
            let uid = Uid::from_raw(ug.uid);
            if setresuid(uid, uid, uid).is_err() {
                return 7;
            }
        }

        if let Some(wd) = &plan.workdir {
            let c = match CString::new(wd.as_os_str().as_encoded_bytes()) {
                Ok(c) => c,
                Err(_) => return 8,
            };
            if unsafe { libc::chdir(c.as_ptr()) } != 0 {
                return 8;
            }
        }

        // exec — only returns on failure.
        let _ = execvpe(argv0, argv, envp);
        9
    }

    fn install_landlock(policy: &super::LandlockPolicy) -> Result<(), ()> {
        let abi = ABI::V2;
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|_| ())?
            .create()
            .map_err(|_| ())?;
        for rule in &policy.rules {
            let fd = match PathFd::new(&rule.path) {
                Ok(fd) => fd,
                // Skip rules whose path doesn't exist yet — a strict default
                // would refuse to start a workload that hasn't materialised
                // its mount points.
                Err(_) => continue,
            };
            let access = match rule.access {
                LandlockAccess::Read => AccessFs::from_read(abi),
                LandlockAccess::ReadWrite => AccessFs::from_all(abi),
            };
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|_| ())?;
        }
        let status = ruleset.restrict_self().map_err(|_| ())?;
        // FullyEnforced or PartiallyEnforced are both acceptable; NotEnforced
        // means the kernel doesn't support landlock at all — caller decides.
        match status.ruleset {
            RulesetStatus::NotEnforced => Err(()),
            _ => Ok(()),
        }
    }

    fn drop_all_caps() -> Result<(), ()> {
        use caps::{clear, CapSet};
        // Order matters: inheritable + ambient cleared first so they can't
        // re-enter via execve, then permitted+effective dropped last.
        clear(None, CapSet::Ambient).map_err(|_| ())?;
        clear(None, CapSet::Inheritable).map_err(|_| ())?;
        clear(None, CapSet::Bounding).map_err(|_| ())?;
        clear(None, CapSet::Effective).map_err(|_| ())?;
        clear(None, CapSet::Permitted).map_err(|_| ())?;
        Ok(())
    }

    fn pre_exec_step_label(code: u8) -> &'static str {
        match code {
            1 => "pre_exec.wait_sync",
            2 => "pre_exec.dup2_stdout",
            3 => "pre_exec.dup2_stderr",
            4 => "pre_exec.landlock_install",
            5 => "pre_exec.drop_caps",
            6 => "pre_exec.setresgid",
            7 => "pre_exec.setresuid",
            8 => "pre_exec.chdir",
            9 => "pre_exec.execvpe",
            _ => "pre_exec.unknown",
        }
    }

    fn report_pre_exec_failure(status_fd: i32, status: u8) -> ! {
        let buf = [status];
        // Best-effort write; we're about to exit either way.
        unsafe { libc::write(status_fd, buf.as_ptr() as *const _, 1) };
        // _exit avoids running parent destructors copied into the child.
        unsafe { libc::_exit(127) }
    }

    fn syscall(label: &'static str) -> impl Fn(nix::errno::Errno) -> SpawnError {
        move |e| SpawnError::Syscall {
            syscall: label,
            source: std::io::Error::from_raw_os_error(e as i32),
        }
    }

    fn io_err(label: &'static str) -> impl Fn(std::io::Error) -> SpawnError {
        move |source| SpawnError::Syscall {
            syscall: label,
            source,
        }
    }

    unsafe fn fd_to_file(fd: std::os::fd::OwnedFd) -> std::fs::File {
        use std::os::fd::FromRawFd;
        let raw = fd.as_raw_fd();
        std::mem::forget(fd);
        std::fs::File::from_raw_fd(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use workload_spec::{
        EnvVar, ImageRef, MeshIdent, MeshLookup, TierTag, VolumeMount, VolumeSource, WorkloadSpec,
    };

    fn base_spec() -> WorkloadSpec {
        let image = ImageRef {
            registry: "localhost".into(),
            repository: "test/svc".into(),
            tag: "latest".into(),
            digest: workload_spec::testing::test_digest(),
        };
        let mut spec = WorkloadSpec::for_forge("t1", image, TierTag("infra".into()), vec![]);
        spec.command = Some(vec!["/usr/local/bin/svc".into()]);
        spec
    }

    #[test]
    fn argv_combines_entrypoint_and_command() {
        let mut spec = base_spec();
        spec.entrypoint = Some(vec!["/sbin/init".into(), "--mode".into()]);
        spec.command = Some(vec!["worker".into(), "--flag".into()]);
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(plan.argv, vec!["/sbin/init", "--mode", "worker", "--flag"]);
    }

    #[test]
    fn argv_command_only_is_ok() {
        let mut spec = base_spec();
        spec.entrypoint = None;
        spec.command = Some(vec!["/usr/local/bin/svc".into()]);
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(plan.argv, vec!["/usr/local/bin/svc"]);
    }

    #[test]
    fn argv_entrypoint_only_is_ok() {
        let mut spec = base_spec();
        spec.entrypoint = Some(vec!["/usr/local/bin/svc".into()]);
        spec.command = None;
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(plan.argv, vec!["/usr/local/bin/svc"]);
    }

    #[test]
    fn argv_empty_is_rejected() {
        let mut spec = base_spec();
        spec.entrypoint = None;
        spec.command = None;
        let err = SandboxPlan::from_spec(&spec).unwrap_err();
        assert!(matches!(err, SpawnError::InvalidSpec(_)));
    }

    #[test]
    fn user_numeric_uid_only_means_gid_matches_uid() {
        let mut spec = base_spec();
        spec.user = Some("1000".into());
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(plan.user, Some(UserGroup { uid: 1000, gid: 1000 }));
    }

    #[test]
    fn user_numeric_uid_gid_pair() {
        let mut spec = base_spec();
        spec.user = Some("1000:2000".into());
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(plan.user, Some(UserGroup { uid: 1000, gid: 2000 }));
    }

    #[test]
    fn user_username_form_rejected() {
        let mut spec = base_spec();
        spec.user = Some("appuser".into());
        assert!(matches!(
            SandboxPlan::from_spec(&spec),
            Err(SpawnError::InvalidSpec(_))
        ));
    }

    #[test]
    fn user_bad_gid_rejected() {
        let mut spec = base_spec();
        spec.user = Some("1000:notanumber".into());
        assert!(matches!(
            SandboxPlan::from_spec(&spec),
            Err(SpawnError::InvalidSpec(_))
        ));
    }

    #[test]
    fn user_none_means_no_uid_drop() {
        let plan = SandboxPlan::from_spec(&base_spec()).unwrap();
        assert!(plan.user.is_none());
    }

    #[test]
    fn env_literal_passes_through() {
        let mut spec = base_spec();
        spec.env = vec![
            EnvVar {
                name: "FOO".into(),
                value: EnvValue::Literal { value: "1".into() },
            },
            EnvVar {
                name: "BAR".into(),
                value: EnvValue::Literal {
                    value: "two".into(),
                },
            },
        ];
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(
            plan.env,
            vec![("FOO".into(), "1".into()), ("BAR".into(), "two".into())]
        );
    }

    #[test]
    fn env_secret_ref_is_rejected() {
        let mut spec = base_spec();
        spec.env = vec![EnvVar {
            name: "DB_PASS".into(),
            value: EnvValue::FromSecret {
                secret: "db".into(),
                key: "password".into(),
            },
        }];
        let err = SandboxPlan::from_spec(&spec).unwrap_err();
        match err {
            SpawnError::InvalidSpec(m) => assert!(m.contains("DB_PASS")),
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn env_mesh_ref_is_rejected() {
        let mut spec = base_spec();
        spec.env = vec![EnvVar {
            name: "PEER_URL".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("peer".into()),
                kind: MeshLookup::Url,
            },
        }];
        let err = SandboxPlan::from_spec(&spec).unwrap_err();
        match err {
            SpawnError::InvalidSpec(m) => assert!(m.contains("PEER_URL")),
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn env_pairs_dedupes_last_write_wins() {
        let plan = SandboxPlan {
            argv: vec!["/bin/true".into()],
            workdir: None,
            env: vec![
                ("FOO".into(), "1".into()),
                ("BAR".into(), "two".into()),
                ("FOO".into(), "overwritten".into()),
            ],
            user: None,
            landlock: LandlockPolicy::default(),
            resources: base_spec().resources,
        };
        assert_eq!(plan.env_pairs(), vec!["FOO=overwritten", "BAR=two"]);
    }

    #[test]
    fn volumes_bind_become_landlock_rules() {
        let mut spec = base_spec();
        spec.volumes = vec![
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: "/srv/data".into(),
                },
                target: PathBuf::from("/data"),
                read_only: false,
            },
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: "/etc/cfg".into(),
                },
                target: PathBuf::from("/etc/cfg"),
                read_only: true,
            },
        ];
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(
            plan.landlock.rules,
            vec![
                LandlockRule {
                    path: PathBuf::from("/data"),
                    access: LandlockAccess::ReadWrite,
                },
                LandlockRule {
                    path: PathBuf::from("/etc/cfg"),
                    access: LandlockAccess::Read,
                },
            ]
        );
    }

    #[test]
    fn volumes_named_and_tmpfs_skipped_from_landlock() {
        let mut spec = base_spec();
        spec.volumes = vec![
            VolumeMount {
                source: VolumeSource::Named { name: "vol".into() },
                target: PathBuf::from("/vol"),
                read_only: false,
            },
            VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 64 },
                target: PathBuf::from("/tmp"),
                read_only: false,
            },
        ];
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert!(plan.landlock.rules.is_empty());
    }

    #[test]
    fn workdir_is_carried_through() {
        let mut spec = base_spec();
        spec.workdir = Some(PathBuf::from("/srv"));
        let plan = SandboxPlan::from_spec(&spec).unwrap();
        assert_eq!(plan.workdir, Some(PathBuf::from("/srv")));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn spawn_off_linux_returns_unsupported() {
        use crate::cgroup::CgroupV2;
        let tmp = tempfile::TempDir::new().unwrap();
        let cg = CgroupV2::new(tmp.path());
        cg.ensure_root().unwrap();
        let plan = SandboxPlan::from_spec(&base_spec()).unwrap();
        let handle = cg
            .create_workload("svc-unsupported", &plan.resources)
            .unwrap();
        let err = spawn(&plan, &handle).unwrap_err();
        assert!(matches!(err, SpawnError::Unsupported));
    }
}
