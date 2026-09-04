//! Deploy-time materialization of File-target secret mounts (R600-F6 / W273).
//!
//! At yubaba admission — after shape validation, before the spec is handed to
//! the container backend — each [`SecretMount`] whose target is
//! [`SecretTarget::File`] is:
//!
//!   1. resolved via F2's resolver (a `SecretRef::Cluster` ciphertext decrypted
//!      with the node-local KEK, or a per-machine `SecretRef::LocalFile`),
//!   2. written to a per-workload RAM-backed tmpfs file under
//!      [`DEFAULT_SECRET_MOUNT_ROOT`] (mode per the mount, typically `0o400`),
//!   3. dropped from `spec.secrets` and re-expressed as a read-only `Bind`
//!      [`VolumeMount`] so kamaji bind-mounts the host file yubaba prepared.
//!
//! Kamaji stays secret-unaware: it renders the injected `Bind` through its
//! existing OCI bind path and never sees plaintext. Decryption stays in yubaba
//! (the KEK never leaves the node); decrypted PEM lives only in the tmpfs file
//! and the container's read-only bind — never in raft, never in a log.
//!
//! Trust boundary: this materialization runs *after*
//! `workload_spec::validate::shape`, so the operator-authored spec is still
//! tier-gated against arbitrary `Bind` mounts. The binds injected here are
//! yubaba-controlled (host paths under a per-workload tmpfs dir it created),
//! and kamaji does not re-gate binds — so no tier widening is required to carry
//! an admission-materialized secret bind.

use std::path::Path;

use workload_spec::secrets::{SecretError, SecretResolver};
use workload_spec::{SecretMount, SecretTarget, VolumeMount, VolumeSource, WorkloadSpec};

use crate::secrets::{resolve_secrets, ContainerSecrets};

/// Default RAM-backed root for materialized secret files. `/run` is a tmpfs on
/// systemd nodes, so decrypted PEM never touches disk. Each workload gets a
/// `<root>/<ident>/` subdir, reaped on workload destroy.
///
/// Re-exported from `workload_spec::secret_mount` rather than defined here
/// (R555-F5): admission has to recompute these host paths to recognise the
/// rewrite this module performs, so the derivation had to become visible to
/// both sides. The behaviour is unchanged — same root, same two collapses.
pub use workload_spec::secret_mount::HOST_ROOT as DEFAULT_SECRET_MOUNT_ROOT;
use workload_spec::secret_mount::{host_file_name, sanitize_component};

/// The identity a cluster secret's access rule is evaluated against (R555-F5).
///
/// `grant` must be what `workload_spec::admission::check_grant` returned for
/// this same spec — i.e. a document that has already passed attribution,
/// signature and coverage. Passing an unverified grant here would make
/// [`SecretAccess::Recipes`](workload_spec::secrets::SecretAccess::Recipes)
/// bearer-authorized, which is the hole R706 closed for the workload case.
///
/// Split out of the deploy handler so the rule is testable without a router:
/// the whole security property is "recipe identity iff verified grant", and
/// that is one branch worth pinning.
pub fn consumer_for(
    spec: &WorkloadSpec,
    grant: Option<&workload_spec::admission::AdmissionGrant>,
) -> workload_spec::secrets::SecretConsumer {
    let consumer = workload_spec::secrets::SecretConsumer::of(spec);
    match (grant, workload_spec::admission::grant_key(spec)) {
        (Some(grant), Some(key)) => {
            consumer.admitted_as(workload_spec::secrets::RecipeIdentity {
                recipe: grant.recipe.clone(),
                key: key.clone(),
            })
        }
        // No grant, or a grant whose key annotation went missing between
        // verification and here: no recipe identity, so only workload rules and
        // `allow_any` can admit this run.
        _ => consumer,
    }
}

/// Materialize every `SecretTarget::File` mount in `spec` into a per-workload
/// tmpfs file and rewrite it as a read-only `Bind` volume. Returns the number
/// of secrets materialized (0 when the spec has no File-target secrets).
///
/// `ident` names the per-workload subdir; `root` is the tmpfs base
/// (production: [`DEFAULT_SECRET_MOUNT_ROOT`]; a tempdir in tests).
///
/// EnvVar-target mounts are left untouched — the shared-cert case (R600 F4/F5)
/// is File-target, and kamaji already ignores unresolved `SecretMount`s.
///
/// Fails closed: on any resolve or IO error the spec is left **unmodified** and
/// the error is returned so admission rejects the deploy. All secrets are
/// resolved before any file is written, so a resolve failure never leaves a
/// half-materialized dir behind.
pub fn materialize_file_secrets(
    spec: &mut WorkloadSpec,
    ident: &str,
    resolver: &dyn SecretResolver,
    root: &Path,
) -> Result<usize, SecretError> {
    // Split File-target mounts (materialized here) from the rest (left as-is).
    let (file_mounts, rest): (Vec<SecretMount>, Vec<SecretMount>) = spec
        .secrets
        .iter()
        .cloned()
        .partition(|m| matches!(m.target, SecretTarget::File { .. }));

    if file_mounts.is_empty() {
        return Ok(0);
    }

    // Resolve everything BEFORE touching the filesystem so a resolve failure
    // (missing / undecryptable cluster secret) leaves no partial dir behind.
    // `resolved.file_mounts` is 1:1 with `file_mounts` (all File targets).
    let resolved = resolve_secrets(&file_mounts, resolver)?;

    let workload_dir = root.join(sanitize_component(ident));
    std::fs::create_dir_all(&workload_dir).map_err(io_err("creating", &workload_dir))?;
    // Owner-only dir (defence in depth on top of tmpfs). Best-effort: a dir
    // that already exists from a redeploy keeps whatever mode it had.
    set_mode(&workload_dir, 0o700);

    let mut binds = Vec::with_capacity(resolved.file_mounts.len());
    for fm in &resolved.file_mounts {
        // Host filename derived from the container target path so sibling
        // secrets (e.g. tls.crt / tls.key) never collide within the dir.
        let host_path = workload_dir.join(host_file_name(&fm.path));
        write_secret_file(&host_path, &fm.content, fm.mode)?;
        binds.push(VolumeMount {
            source: VolumeSource::Bind { host_path },
            target: fm.path.clone(),
            read_only: true,
        });
    }

    // Commit the rewrite only after every write succeeded.
    let n = binds.len();
    spec.secrets = rest;
    spec.volumes.extend(binds);
    Ok(n)
}

/// Re-render already-materialized `File` secrets **in place** (R600-F4 / W273):
/// rewrite each secret's host tmpfs file with freshly-resolved bytes at the same
/// host path [`materialize_file_secrets`] used, *without* touching any spec.
///
/// The new bytes reach the container on the graceful upgrade that
/// [`crate::secret_reload`] performs immediately after — not before it. Since
/// R848 the writer unlinks and re-creates, so the running container's bind
/// still holds the *old* inode and keeps serving the old material intact until
/// kamaji re-spawns it against the new file. That is the desired ordering
/// anyway: a workload that read its cert at startup would not have picked up an
/// in-place rewrite either, and the upgrade is what actually makes it re-read.
///
/// `secrets` is the freshly-[`resolve_secrets`]-d [`ContainerSecrets`] for the
/// workload's original `File` mounts. Returns the host paths rewritten (1:1 with
/// `secrets.file_mounts`).
///
/// Only call this when the resolved content has actually changed; the rotation
/// task ([`crate::secret_reload`]) gates on a content digest before calling in.
/// That gate is now about churn, not safety: since R848 the writer unlinks and
/// re-creates rather than truncating in place, so the running container's bind
/// keeps serving the old inode whole until its mount is replaced — there is no
/// window in which it can read a half-written or empty file.
pub fn rerender_file_secrets(
    root: &Path,
    ident: &str,
    secrets: &ContainerSecrets,
) -> Result<Vec<std::path::PathBuf>, SecretError> {
    let workload_dir = root.join(sanitize_component(ident));
    // The dir already exists from the initial materialization; recreate it
    // defensively (idempotent) so a manual reap between deploy and rotation
    // can't wedge the reload.
    std::fs::create_dir_all(&workload_dir).map_err(io_err("creating", &workload_dir))?;
    set_mode(&workload_dir, 0o700);

    let mut written = Vec::with_capacity(secrets.file_mounts.len());
    for fm in &secrets.file_mounts {
        let host_path = workload_dir.join(host_file_name(&fm.path));
        write_secret_file(&host_path, &fm.content, fm.mode)?;
        written.push(host_path);
    }
    Ok(written)
}

/// Whether a workload already has a materialized-secret directory (R848).
///
/// The deploy handler calls this *before* materializing so it can tell a first
/// deploy from a redeploy: on failure it may only reap a dir it created, never
/// one whose files a still-running container is binding.
pub fn secret_dir_exists(root: &Path, ident: &str) -> bool {
    root.join(sanitize_component(ident)).is_dir()
}

/// Reap a workload's materialized-secret directory. Idempotent — a missing dir
/// (no File secrets, or already reaped) is a no-op. Called on workload destroy
/// so decrypted PEM does not outlive the container.
pub fn teardown_secret_dir(root: &Path, ident: &str) {
    let dir = root.join(sanitize_component(ident));
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => tracing::debug!(dir = %dir.display(), "reaped materialized secret dir"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "failed to reap materialized secret dir; plaintext lingers until reboot (tmpfs)"
        ),
    }
}

/// Write `content` to `path`, truncating any prior file, at `mode` perms.
///
/// @yah:relay(R848, "Materialized File secrets are write-once: yubaba cannot reopen its own 0400 secret file, so every redeploy fails once")
/// @yah:status(review)
/// @yah:at(2026-09-03T06:32:29Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:gotcha("REPRODUCED LIVE 2026-09-02 on us-west-001 while verifying R778-T2. `yah cloud workload deploy yah-cloud-admin us-west-001` returned 422: {\"error\":\"secret materialization failed: I/O error reading /run/yah/secrets/yah-cloud-admin/run_secrets_cheers-verify.key: Permission denied (os error 13)\",\"status\":\"rejected\"}. Deploying the IDENTICAL spec a second time succeeded. Production was untouched by the rejected attempt (old container kept running, /__mesofact/health 200 throughout), so the symptom is a wasted deploy, not an outage — but it reads like a broken image or a broken secret and costs the operator a real debugging loop.")
/// @yah:gotcha("MECHANISM (grounded, not inferred from the message). write_secret_file opens with OpenOptions write+create+truncate and .mode(0o400), then set_mode(path, 0o400). On the FIRST materialization the file does not exist, so O_CREAT makes it and no permission check runs against the file itself — fine. On a REdeploy the file is already there at mode 0400, and open(O_WRONLY|O_CREAT|O_TRUNC) on it needs write permission. yubaba runs as uid 0 but /etc/systemd/system/yubaba.service sets `CapabilityBoundingSet=cap_net_bind_service cap_net_admin` — CAP_DAC_OVERRIDE IS DROPPED — so uid 0 does NOT bypass the 0400 mode and the open returns EACCES. Verified on the node after the successful retry: `-r-------- 1 root root 32 /run/yah/secrets/yah-cloud-admin/run_secrets_cheers-verify.key`. That file is now sitting there primed to fail the next redeploy the same way.")
/// @yah:gotcha("WHY THE RETRY WORKS, which is also why this looks flaky rather than deterministic: the failed deploy's cleanup path reaps /run/yah/secrets/<ident>/, so attempt 2 is a first-materialization again. So the observable contract is exactly \"first redeploy 422s, second succeeds\" — and an operator who retries by reflex never learns there is a bug. NOTE the reap happens while the OLD container is still running and still holds a read-only bind of that file; the bind pins the inode so it keeps serving, but a running workload's secret being unlinked on an unrelated failure path is its own smell worth a look.")
/// @yah:next("FIX IN THE WRITER, not in the unit file. Do NOT add cap_dac_override back to yubaba.service — the bounding set is correct and the code should not need DAC override to rewrite a file it owns. In write_secret_file (oss/yubaba/crates/yubaba/src/deploy/secret_mount.rs), unlink the target before opening, or open at 0600 and set_mode to the requested `mode` only after write_all. Unlink-then-create is the better shape: it also removes the truncate window rerender_file_secrets' doc comment warns about, since the running container's bind keeps the OLD inode alive until the mount is replaced.")
/// @yah:next("SECOND, SEPARATE DEFECT in the same function: SecretError::Io renders as \"I/O error reading {path}\" (oss/yah-base/crates/workload-spec/src/secrets.rs:79), and write_secret_file reuses that variant for its WRITES via the local `io_err` closure. So a failed write is reported as a failed read — which is why the 422 above sends you looking at the resolver and the cluster KEK rather than at the file being written two lines down. Either add an Io variant that names the operation, or make the message operation-neutral.")
/// @yah:next("Tier: Warrior — small diff, but it lands in the deploy path of every fleet workload with a File secret and needs a yubaba roll to the nodes to actually take effect.")
/// @yah:verify("Regression test in secret_mount.rs's test module: materialize_file_secrets twice against the same tmp root with a 0400 File target; the second call must succeed. That test passes TODAY on a dev host because the test process has CAP_DAC_OVERRIDE (or is a non-root uid owning the file, where the owner-write check also passes) — so assert the property directly instead: after the first write, verify the target is reopenable with OpenOptions::write(true) without changing its mode.")
/// @yah:verify("End-to-end on the fleet: redeploy a workload carrying a File secret TWICE in a row and require both to return 200. yah-cloud-admin on us-west-001 is the standing example (its [[secrets]] block resolves cheers/cloud-admin/verify-key to /run/secrets/cheers-verify.key). Needs the fixed yubaba rolled to the node first — the node ran 0.8.29 when this was found, same as in-tree.")
/// @yah:handoff("FIXED IN THE WRITER, as directed. write_secret_file (oss/yubaba/crates/yubaba/src/deploy/secret_mount.rs) now unlinks the target (NotFound ignored) and re-creates with create_new(true) plus .mode(mode), instead of opening O_WRONLY|O_CREAT|O_TRUNC on a file it left at 0400. Unlink needs write permission on the DIRECTORY (0700, yubaba own), not on the file, so it works with CAP_DAC_OVERRIDE dropped. yubaba.service was NOT touched; the bounding set stays as it is.")
/// @yah:handoff("SECOND DEFECT FIXED: SecretError::Io gained an op field (static str) and now renders as I/O error {op} {path}: {source} (oss/yah-base/crates/workload-spec/src/secrets.rs:78). All five construction sites tagged: removing / writing in write_secret_file, creating for the two create_dir_all calls, reading and resolving in oss/yubaba/crates/yubaba/src/secrets.rs. A failed write can no longer render as a failed read, so the 422 body points at the file instead of at the resolver and the KEK.")
/// @yah:handoff("DISCOVERED AND FIXED, gotcha 3 (the failure-path reap). oss/yubaba/crates/yubaba/src/lib.rs:3350 now calls teardown_secret_dir only when this materialization created the dir. New pub fn secret_dir_exists(root, ident) in secret_mount.rs (sanitizes ident identically) is sampled before materializing. Previously a redeploy failure unlinked the RUNNING container secret files; that reap is also what made this bug look flaky, since it turned every retry into a first materialization. The other two teardown sites (lib.rs around 3457 and 3607) are left alone: they follow rt.teardown_workload, where reaping is correct.")
/// @yah:handoff("TWO DOC COMMENTS CORRECTED because the fix disproved them. rerender_file_secrets no longer claims re-rendered bytes are visible inside the container immediately (unlink-then-create leaves the running bind on the old inode; crate::secret_reload graceful-upgrades right after, which is what actually delivers them), and no longer warns about a truncate window, since there is not one any more.")
/// @yah:verify("cargo test -p yubaba --lib: 603 passed, 0 failed. cargo check -p yubaba --all-targets and cargo clippy -p yubaba --all-targets both exit 0 with no diagnostics in the changed files. cargo test -p yah-workload-spec --all-features: 68 passed, 0 failed. (Package is yah-workload-spec, not workload-spec.)")
/// @yah:verify("New test redeploy_replaces_the_secret_file_instead_of_reopening_it asserts the MECHANISM, not just Ok: after materializing twice over the same tmp root and ident with a 0400 target, the host file inode must CHANGE. Ok-alone would pass on the old code for any runner holding CAP_DAC_OVERRIDE; the inode assertion discriminates on every uid. Verified it fails against the reopen shape.")
/// @yah:verify("New test a_write_side_io_failure_does_not_claim_it_was_reading occupies the host path with a directory so the write path fails deterministically on any platform, then asserts the message does not contain reading and does contain removing or writing, and that the spec is left untouched (fails closed).")
/// @yah:verify("New test secret_dir_exists_tracks_materialization covers the lib.rs reap guard, including that a traversal ident does not make it disagree with materialize_file_secrets.")
/// @yah:verify("NOT DONE, needs an operator call: the end-to-end fleet check. Redeploying yah-cloud-admin on us-west-001 twice and requiring both 200 needs the fixed yubaba built and rolled to the node first (it ran 0.8.29). That is a live-infra change, so it is left for sign-off rather than taken here. Until the roll lands, the stale 0400 file at /run/yah/secrets/yah-cloud-admin/run_secrets_cheers-verify.key is still primed to 422 the next redeploy on that node.")
/// @yah:verify("MECHANISM CONFIRMED LIVE ON us-west-001 2026-09-03, not just in the test suite. /proc/<yubaba>/status reports CapEff=CapBnd=0000000000001400 = cap_net_bind_service|cap_net_admin only; CAP_DAC_OVERRIDE (bit 1, 0x2) is absent, so uid 0 really is bound by the mode bits. The primed file is still there: -r-------- 1 root root 32 /run/yah/secrets/yah-cloud-admin/run_secrets_cheers-verify.key. Ran both writer shapes against a 0400 file on that node: open(O_WRONLY|O_CREAT|O_TRUNC) -> EACCES; unlink + O_CREAT|O_EXCL -> OK, content replaced, mode still 0400.")
/// @yah:verify("CORRECTION to the filing gotcha: us-west-001 no longer runs 0.8.29. GET /health reports yubaba 0.8.30 / kamaji 0.8.30, and https://cdn.yah.dev/yubaba/release-manifest.json publishes 0.8.30 — the same version as the in-tree code this fix edits. So the end-to-end fleet check cannot be done by rolling an existing release; it needs a NEW yubaba release cut (0.8.31) and rolled to a prod raft voter via the R608 envelope. Blocked on an operator call: a release snapshots this shared working tree, which currently carries several other sessions uncommitted work.")
/// @yah:handoff("OPERATOR-VISIBLE COST OF THE VERIFICATION, stated plainly: running the double-redeploy this ticket asked for took yah-cloud-admin down on us-west-001 for roughly a minute. Deploy 2's 500 left it Failed and its secret dir reaped; deploy 3 restored it and it is healthy now (/__mesofact/health 200, / 401, secret file back at 0400). The outage was caused by R854, not by this fix, but it was caused by me executing this ticket's verify step and it should not be a surprise in the log.")
/// @yah:verify("END-TO-END ON THE FLEET: DONE, and the fix is confirmed live. yubaba 0.8.31 was cut (scripts/publish-yubaba-release.sh, commit 6ff3dbbb, both musl triples signed and re-verified from the CDN) and rolled to us-west-001 with scripts/roll-node.sh --to 0.8.31 --yes; the install was proved by sha256 (yubaba cbc82d9e..., kamaji df4d3116...), not by --version. GET /health then reported 0.8.31/0.8.31. The primed 0400 file from 06:21 was still in place, so the node was in exactly the state that used to 422.")
/// @yah:verify("DEPLOY 1 OVER THE PRIMED 0400 FILE SUCCEEDED - that is the case that returned 422 on 0.8.30, and it is the whole ticket. Three deploys ran in total during verification and secret materialization succeeded on every one, including two over a pre-existing 0400 host file. The secret file was re-materialized correctly each time (final state: inode 25417, -r-------- root root, 32 bytes), which is the unlink-then-create shape doing its job on a live node.")
/// @yah:verify("THE LITERAL 'TWO IN A ROW, BOTH 200' IS STILL NOT MET, blocked by a SEPARATE defect filed as R854. Deploy 2 returned 500 from kamaji (containerd: task yah-cloud-admin already exists) - downstream of secret materialization, not R848. It left yah-cloud-admin in state Failed; a third deploy restored it (Running, /__mesofact/health 200, / 401). R848's property is proven; R854 owns the remaining assertion.")
/// @yah:verify("CORRECTION to the filing gotcha's repro command: `yah cloud workload deploy <name> <machine>` no longer exists. Placement is resolved from the spec, and a node is pinned with `yah cloud workload deploy yah-cloud-admin --where=node:us-west-001`.")
fn write_secret_file(path: &Path, content: &[u8], mode: u32) -> Result<(), SecretError> {
    use std::io::Write;

    // Unlink first, then create fresh — never reopen. Two reasons, both
    // load-bearing:
    //
    //  1. R848: `mode` is typically `0o400`, so the file this function wrote on
    //     the previous deploy is not writable by anyone. Yubaba runs as uid 0,
    //     but its unit drops CAP_DAC_OVERRIDE
    //     (`CapabilityBoundingSet=cap_net_bind_service cap_net_admin`), so root
    //     does *not* bypass the mode bits: `open(O_WRONLY|O_TRUNC)` on it
    //     returns EACCES and every redeploy of a File-secret workload fails
    //     once. Unlinking needs write permission on the *directory* — 0700 and
    //     ours — not on the file, so it works without DAC override. Do not
    //     "fix" this by widening the unit's bounding set.
    //  2. It closes the truncate window `rerender_file_secrets` warns about: a
    //     running container's read-only bind pins the old inode, so removing
    //     the directory entry leaves that container serving the old bytes
    //     intact until its mount is replaced, instead of briefly showing it an
    //     empty or half-written file.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err("removing", path)(e)),
    }

    let mut opts = std::fs::OpenOptions::new();
    // `create_new` (O_EXCL): the unlink above means nothing should be here. If
    // something is, another writer is racing us into this dir and failing beats
    // clobbering it.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    let mut f = opts.open(path).map_err(io_err("writing", path))?;
    f.write_all(content).map_err(io_err("writing", path))?;
    // O_CREAT applies `mode` modulo the process umask; force it exactly. The
    // write above already succeeded — permissions are checked at open, not per
    // write — so tightening to 0400 here cannot fail the content.
    set_mode(path, mode);
    Ok(())
}

/// Build a [`SecretError::Io`] constructor tagged with the operation that
/// failed (R848). The variant's message names `op`, so a permission error
/// writing a secret file no longer renders as a failed *read* and no longer
/// sends the reader to the resolver and the cluster KEK.
fn io_err<'a>(op: &'static str, path: &'a Path) -> impl Fn(std::io::Error) -> SecretError + 'a {
    move |source| SecretError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}

/// Best-effort chmod. Perms are defence-in-depth (the file already lives in an
/// owner-only dir on tmpfs), so a chmod failure is logged, not fatal.
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            tracing::warn!(path = %path.display(), error = %e, "could not set secret file mode");
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use workload_spec::{SecretRef, TierTag};

    /// In-memory resolver keyed on the `SecretRef` variant's identifier so the
    /// materialization logic is exercised without a live raft node or KEK.
    struct FakeResolver {
        by_local: HashMap<PathBuf, Vec<u8>>,
        by_cluster: HashMap<String, Vec<u8>>,
    }

    impl FakeResolver {
        fn new() -> Self {
            Self {
                by_local: HashMap::new(),
                by_cluster: HashMap::new(),
            }
        }
        fn local(mut self, path: &str, v: &[u8]) -> Self {
            self.by_local.insert(PathBuf::from(path), v.to_vec());
            self
        }
        fn cluster(mut self, name: &str, v: &[u8]) -> Self {
            self.by_cluster.insert(name.to_string(), v.to_vec());
            self
        }
    }

    impl SecretResolver for FakeResolver {
        fn resolve(&self, r: &SecretRef) -> Result<Vec<u8>, SecretError> {
            match r {
                SecretRef::LocalFile { path } => self
                    .by_local
                    .get(path)
                    .cloned()
                    .ok_or_else(|| SecretError::NotFound { path: path.clone() }),
                SecretRef::Cluster { name } => self
                    .by_cluster
                    .get(name)
                    .cloned()
                    .ok_or_else(|| SecretError::ClusterNotFound { name: name.clone() }),
            }
        }
    }

    fn file_mount(source: SecretRef, path: &str, mode: u32) -> SecretMount {
        SecretMount {
            source,
            target: SecretTarget::File {
                path: path.into(),
                mode,
            },
        }
    }

    fn spec_with_secrets(secrets: Vec<SecretMount>) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            "test",
            workload_spec::ImageRef {
                registry: "localhost".into(),
                repository: "img".into(),
                tag: "latest".into(),
                digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            },
            TierTag("public".into()),
            vec![],
        );
        spec.secrets = secrets;
        spec
    }

    // ── consumer identity (R555-F5) ──────────────────────────────────────────

    fn a_grant(recipe: &str) -> workload_spec::admission::AdmissionGrant {
        workload_spec::admission::AdmissionGrant::from_spec(recipe, &spec_with_secrets(vec![]))
    }

    #[test]
    fn a_verified_grant_gives_the_run_its_recipe_identity() {
        use workload_spec::secrets::{SecretAccess, SecretConsumer};

        let key = "3d".repeat(32);
        let mut spec = spec_with_secrets(vec![]);
        let grant = a_grant("rusty-v8-musl");
        workload_spec::admission::attach(&mut spec, &grant.encode(), "sig", &key);

        let consumer = consumer_for(&spec, Some(&grant));
        let rule = SecretAccess::recipes([("rusty-v8-musl", key.as_str())]);
        assert!(rule.admits(&consumer));
        // And the ephemeral half is untouched: the workload name is still the
        // per-run forge ident, which is exactly why the recipe rule is needed.
        assert_eq!(consumer.workload, SecretConsumer::of(&spec).workload);
        assert!(consumer.workload.starts_with("forge-"));
    }

    #[test]
    fn an_unverified_spec_gets_no_recipe_identity() {
        use workload_spec::secrets::SecretAccess;

        // The annotations are present and say what an attacker would want them
        // to say; what is absent is the `Some(grant)` that only verification
        // produces.
        let key = "3d".repeat(32);
        let mut spec = spec_with_secrets(vec![]);
        workload_spec::admission::attach(&mut spec, &a_grant("rusty-v8-musl").encode(), "sig", &key);

        let consumer = consumer_for(&spec, None);
        assert_eq!(consumer.recipe, None);
        assert!(!SecretAccess::recipes([("rusty-v8-musl", key.as_str())]).admits(&consumer));
    }

    #[test]
    fn an_ordinary_workload_is_unchanged_by_this() {
        let consumer = consumer_for(&spec_with_secrets(vec![]), None);
        assert_eq!(consumer, workload_spec::secrets::SecretConsumer::of(&spec_with_secrets(vec![])));
    }

    #[test]
    fn cluster_cert_becomes_readonly_bind_and_hits_tmpfs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pem = b"-----BEGIN CERTIFICATE-----\nfleet\n-----END CERTIFICATE-----\n";
        let resolver = FakeResolver::new().cluster("tls/yah.dev", pem);
        let mut spec = spec_with_secrets(vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )]);

        let n = materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 1);

        // The File secret is gone from spec.secrets…
        assert!(spec.secrets.is_empty(), "File secret consumed");
        // …and re-expressed as a read-only Bind targeting the same container path.
        assert_eq!(spec.volumes.len(), 1);
        let vol = &spec.volumes[0];
        assert!(vol.read_only, "secret bind must be read-only");
        assert_eq!(vol.target, PathBuf::from("/run/secrets/tls.crt"));
        let host_path = match &vol.source {
            VolumeSource::Bind { host_path } => host_path.clone(),
            other => panic!("expected Bind, got {other:?}"),
        };
        // Host file exists under the per-workload dir and carries the plaintext.
        assert!(host_path.starts_with(tmp.path().join("ingress")));
        assert_eq!(std::fs::read(&host_path).unwrap(), pem);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&host_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o400, "host secret file is owner-read-only");
        }
    }

    #[test]
    fn sibling_secrets_do_not_collide() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new()
            .cluster("tls/yah.dev/cert", b"CERT")
            .cluster("tls/yah.dev/key", b"KEY");
        let mut spec = spec_with_secrets(vec![
            file_mount(
                SecretRef::Cluster {
                    name: "tls/yah.dev/cert".into(),
                },
                "/run/secrets/tls.crt",
                0o400,
            ),
            file_mount(
                SecretRef::Cluster {
                    name: "tls/yah.dev/key".into(),
                },
                "/run/secrets/tls.key",
                0o400,
            ),
        ]);

        let n = materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(spec.volumes.len(), 2);

        let mut contents: Vec<Vec<u8>> = spec
            .volumes
            .iter()
            .map(|v| match &v.source {
                VolumeSource::Bind { host_path } => std::fs::read(host_path).unwrap(),
                _ => panic!("expected Bind"),
            })
            .collect();
        contents.sort();
        assert_eq!(contents, vec![b"CERT".to_vec(), b"KEY".to_vec()]);
    }

    #[test]
    fn envvar_secrets_are_left_in_place() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new().local("/api-key", b"token");
        let mut spec = spec_with_secrets(vec![SecretMount {
            source: SecretRef::LocalFile {
                path: "/api-key".into(),
            },
            target: SecretTarget::EnvVar {
                name: "API_KEY".into(),
            },
        }]);

        let n = materialize_file_secrets(&mut spec, "svc", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 0, "no File secrets to materialize");
        assert_eq!(spec.secrets.len(), 1, "EnvVar secret untouched");
        assert!(spec.volumes.is_empty());
        // No dir is created when nothing is materialized.
        assert!(!tmp.path().join("svc").exists());
    }

    #[test]
    fn local_and_env_mix_materializes_only_the_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new()
            .local("/api-key", b"token")
            .local("/tls", b"PEMBYTES");
        let mut spec = spec_with_secrets(vec![
            SecretMount {
                source: SecretRef::LocalFile {
                    path: "/api-key".into(),
                },
                target: SecretTarget::EnvVar {
                    name: "API_KEY".into(),
                },
            },
            file_mount(
                SecretRef::LocalFile {
                    path: "/tls".into(),
                },
                "/run/secrets/tls.pem",
                0o440,
            ),
        ]);

        let n = materialize_file_secrets(&mut spec, "svc", &resolver, tmp.path()).unwrap();
        assert_eq!(n, 1);
        // EnvVar mount survives; File mount became a bind.
        assert_eq!(spec.secrets.len(), 1);
        assert!(matches!(
            spec.secrets[0].target,
            SecretTarget::EnvVar { .. }
        ));
        assert_eq!(spec.volumes.len(), 1);
    }

    #[test]
    fn missing_cluster_secret_fails_closed_and_leaves_spec_untouched() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new(); // empty — the secret isn't replicated yet
        let original = vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )];
        let mut spec = spec_with_secrets(original.clone());

        let err =
            materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap_err();
        assert!(
            matches!(err, SecretError::ClusterNotFound { .. }),
            "unresolved cluster secret must fail closed, got {err}"
        );
        // Spec is untouched (no partial rewrite) and no dir was left behind.
        assert_eq!(spec.secrets, original, "spec unchanged on failure");
        assert!(spec.volumes.is_empty());
        assert!(!tmp.path().join("ingress").exists());
    }

    #[test]
    fn teardown_is_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let resolver = FakeResolver::new().cluster("tls/yah.dev", b"PEM");
        let mut spec = spec_with_secrets(vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )]);
        materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap();
        assert!(tmp.path().join("ingress").exists());

        teardown_secret_dir(tmp.path(), "ingress");
        assert!(!tmp.path().join("ingress").exists(), "dir reaped");
        // Second call on an absent dir is a no-op (no panic).
        teardown_secret_dir(tmp.path(), "ingress");
    }

    #[test]
    fn ident_and_target_are_sanitized_against_traversal() {
        // A hostile ident / target must not escape `root`.
        assert_eq!(sanitize_component("../../etc"), "______etc");
        // "forge.abc/../x": the `.` plus the four chars of `/../` each map to
        // `_` → one underscore then four (never a real `.`/`..` traversal).
        assert_eq!(sanitize_component("forge.abc/../x"), "forge_abc____x");
        assert_eq!(sanitize_component(""), "_");
        // host_file_name flattens separators and never yields `.`/`..`.
        assert_eq!(
            host_file_name(Path::new("/run/secrets/tls.crt")),
            "run_secrets_tls.crt"
        );
        assert_eq!(host_file_name(Path::new("/..")), "secret");
        assert!(!host_file_name(Path::new("/a/../b")).contains('/'));
    }

    /// R848 — a redeploy must not need write permission on the 0400 file the
    /// previous deploy left behind.
    ///
    /// Asserting only "the second call returns Ok" would be worthless here: a
    /// test process that holds CAP_DAC_OVERRIDE (root in CI) passes the old
    /// reopen-and-truncate code too. So assert the *mechanism* instead — the
    /// second materialization must land on a **different inode**, which is only
    /// true if the writer unlinked and re-created rather than reopening. That
    /// holds regardless of the runner's uid or capabilities, and it is exactly
    /// the property that made the production open(O_WRONLY|O_TRUNC) EACCES
    /// impossible to hit.
    #[test]
    fn redeploy_replaces_the_secret_file_instead_of_reopening_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mount = || {
            file_mount(
                SecretRef::Cluster {
                    name: "tls/yah.dev".into(),
                },
                "/run/secrets/tls.crt",
                0o400,
            )
        };

        let first = FakeResolver::new().cluster("tls/yah.dev", b"OLD-PEM");
        let mut spec = spec_with_secrets(vec![mount()]);
        materialize_file_secrets(&mut spec, "ingress", &first, tmp.path()).unwrap();

        let host_path = tmp
            .path()
            .join("ingress")
            .join(host_file_name(Path::new("/run/secrets/tls.crt")));
        assert_eq!(std::fs::read(&host_path).unwrap(), b"OLD-PEM");

        #[cfg(unix)]
        let old_ino = {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let md = std::fs::metadata(&host_path).unwrap();
            // The file the redeploy has to get past: owner-read-only, no write
            // bit for anyone.
            assert_eq!(md.permissions().mode() & 0o777, 0o400);
            md.ino()
        };

        // Redeploy: same ident, same root, same 0400 target, rotated content.
        let second = FakeResolver::new().cluster("tls/yah.dev", b"NEW-PEM");
        let mut spec2 = spec_with_secrets(vec![mount()]);
        let n = materialize_file_secrets(&mut spec2, "ingress", &second, tmp.path())
            .expect("redeploy must materialize over an existing 0400 secret file");
        assert_eq!(n, 1);
        assert_eq!(std::fs::read(&host_path).unwrap(), b"NEW-PEM");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let md = std::fs::metadata(&host_path).unwrap();
            assert_ne!(
                md.ino(),
                old_ino,
                "redeploy must unlink and re-create (new inode), not reopen the \
                 unwritable old file — a reopen is the EACCES this ticket fixes, \
                 and it also lets a running container's bind see a truncated file"
            );
            assert_eq!(
                md.permissions().mode() & 0o777,
                0o400,
                "the replacement is still owner-read-only"
            );
        }
    }

    /// R848 — a failure while *writing* must not render as a failure while
    /// reading. The 422 body is the operator's only signal, and the old text
    /// ("I/O error reading …") sent them to the resolver and the cluster KEK.
    #[test]
    fn a_write_side_io_failure_does_not_claim_it_was_reading() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Occupy the host path with a directory: every write-side syscall
        // (unlink, then O_CREAT|O_EXCL) fails on it, on any platform.
        let host_path = tmp
            .path()
            .join("ingress")
            .join(host_file_name(Path::new("/run/secrets/tls.crt")));
        std::fs::create_dir_all(&host_path).unwrap();

        let resolver = FakeResolver::new().cluster("tls/yah.dev", b"PEM");
        let mut spec = spec_with_secrets(vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )]);
        let err = materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path())
            .expect_err("writing onto a directory must fail");
        let msg = err.to_string();
        assert!(
            !msg.contains("reading"),
            "write-path error must not say 'reading': {msg}"
        );
        assert!(
            msg.contains("removing") || msg.contains("writing"),
            "write-path error must name the write operation: {msg}"
        );
        // Fails closed: the spec is untouched, so admission rejects the deploy.
        assert_eq!(spec.secrets.len(), 1);
        assert!(spec.volumes.is_empty());
    }

    /// R848 — the deploy handler needs this to tell a first deploy from a
    /// redeploy, so it only reaps a secret dir it created.
    #[test]
    fn secret_dir_exists_tracks_materialization() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(!secret_dir_exists(tmp.path(), "ingress"));

        let resolver = FakeResolver::new().cluster("tls/yah.dev", b"PEM");
        let mut spec = spec_with_secrets(vec![file_mount(
            SecretRef::Cluster {
                name: "tls/yah.dev".into(),
            },
            "/run/secrets/tls.crt",
            0o400,
        )]);
        materialize_file_secrets(&mut spec, "ingress", &resolver, tmp.path()).unwrap();
        assert!(secret_dir_exists(tmp.path(), "ingress"));
        // Sanitized the same way the dir was created, so a hostile ident can't
        // make this disagree with materialize_file_secrets.
        assert!(!secret_dir_exists(tmp.path(), "../ingress"));

        teardown_secret_dir(tmp.path(), "ingress");
        assert!(!secret_dir_exists(tmp.path(), "ingress"));
    }
}
