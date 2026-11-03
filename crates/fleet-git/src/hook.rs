//! `pre-receive` / `post-receive`: a thin client in the repo, the decisions in
//! the supervisor (W363 §2 "Ack semantics").
//!
//! git runs `fleet-git hook <stage>` in the repo with the ref updates on stdin.
//! The client forwards them over `$FLEET_GIT_SOCK` (one JSON line each way) to
//! the supervisor, which already holds that repo's push lock, and exits with
//! its verdict. The supervisor owns ref policy and the coarse fence; the
//! durable step is the [`PushLog`] ([`crate::stream::R2Log`]).

use crate::auth::RefGrant;
use crate::fence::{Fence, FenceCheck};
use crate::repo;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

pub const SOCK_ENV: &str = "FLEET_GIT_SOCK";
/// The token's [`RefGrant`], set by the supervisor on http-backend (which runs
/// with a cleared env, so a client cannot supply it).
pub const REFS_ENV: &str = "FLEET_GIT_REFS";
/// The token's `git_ref` claim (R969-T12), set the same way; unset = no claim.
pub const REF_ONLY_ENV: &str = "FLEET_GIT_REF_ONLY";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    PreReceive,
    PostReceive,
}

impl Stage {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pre-receive" => Some(Stage::PreReceive),
            "post-receive" => Some(Stage::PostReceive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub refname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookRequest {
    pub stage: Stage,
    /// The hook's cwd, which receive-pack sets to the repo.
    pub repo_dir: PathBuf,
    /// `$GIT_QUARANTINE_PATH`: where this push's objects (and pack) are until
    /// pre-receive returns. Absent for pushes that carry no objects.
    pub quarantine: Option<PathBuf>,
    /// `$REMOTE_USER`: the token `sub` the supervisor handed http-backend.
    pub pusher: String,
    /// `$FLEET_GIT_REFS`: the ref namespaces the pusher's token may write.
    pub grant: RefGrant,
    /// `$FLEET_GIT_REF_ONLY`: the one ref (or `/`-terminated prefix) the
    /// pusher's token is confined to, if it carries a `git_ref` claim.
    #[serde(default)]
    pub only: Option<String>,
    pub updates: Vec<RefUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookReply {
    pub ok: bool,
    pub message: String,
}

/// One push the supervisor has accepted, as handed to the [`PushLog`].
#[derive(Debug, Clone)]
pub struct AcceptedPush {
    pub repo: String,
    pub repo_dir: PathBuf,
    pub quarantine: Option<PathBuf>,
    pub pusher: String,
    pub updates: Vec<RefUpdate>,
    pub epoch: u64,
}

/// The durable step of a push, implemented by [`crate::stream::R2Log`].
///
/// `append` runs inside `pre-receive` after policy and the coarse fence pass
/// and before git moves any ref; an `Err` refuses the push. It is W363 §2
/// steps 3–4 (`PUT Create packs/<name>.pack`, then `PUT Create
/// journal/<seq+1>.json`, `AlreadyExists` = fence loss). `committed` runs in
/// `post-receive`, after the refs moved (step 5: advance the volume marker).
#[async_trait::async_trait]
pub trait PushLog: Send + Sync {
    async fn append(&self, push: &AcceptedPush) -> Result<()>;
    async fn committed(&self, push: &AcceptedPush) -> Result<()>;
}

// ---------------------------------------------------------------- client side

/// `fleet-git hook <stage>`: what git runs. Returns the process exit code.
pub fn run_client(stage: Stage) -> i32 {
    match client(stage) {
        Ok(reply) => {
            if !reply.message.is_empty() {
                eprintln!("{}", reply.message);
            }
            if reply.ok {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("fleet-git: {stage:?} hook failed: {e:#}");
            1
        }
    }
}

fn client(stage: Stage) -> Result<HookReply> {
    let sock = std::env::var_os(SOCK_ENV).with_context(|| format!("${SOCK_ENV} is not set"))?;
    let mut updates = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        updates.push(parse_update(&line)?);
    }
    let req = HookRequest {
        stage,
        repo_dir: std::env::current_dir()?.canonicalize()?,
        quarantine: std::env::var_os("GIT_QUARANTINE_PATH").map(PathBuf::from),
        pusher: std::env::var("REMOTE_USER").unwrap_or_default(),
        // Unset grants nothing: a hook not run under the supervisor writes nowhere.
        grant: RefGrant::from_env(&std::env::var(REFS_ENV).unwrap_or_default()),
        only: std::env::var(REF_ONLY_ENV).ok(),
        updates,
    };
    let mut stream = std::os::unix::net::UnixStream::connect(&sock)
        .with_context(|| format!("connecting to {}", Path::new(&sock).display()))?;
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply)?;
    serde_json::from_str(&reply).context("malformed reply from the supervisor")
}

pub fn parse_update(line: &str) -> Result<RefUpdate> {
    let mut it = line.split_whitespace();
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(old), Some(new), Some(refname), None) => Ok(RefUpdate {
            old: old.into(),
            new: new.into(),
            refname: refname.into(),
        }),
        _ => bail!("malformed hook input line {line:?}"),
    }
}

// ---------------------------------------------------------------- policy

pub fn is_zero(oid: &str) -> bool {
    !oid.is_empty() && oid.bytes().all(|b| b == b'0')
}

/// W363 §2 step 1, then the token's [`RefGrant`] (W366 §5): `refs/qed/**` and
/// `refs/relays/**` are free-for-all within their grant (relay tips rewrite on
/// refresh, so non-fast-forward and delete are allowed); `refs/heads/*` and
/// `refs/tags/*` need the `heads` grant and stay fast-forward only.
/// `is_ancestor(old, new)` is `git merge-base --is-ancestor`.
///
/// @yah:ticket(R978-F4, "fleet-git ref-scoped write claim + refs/relays/** namespace: only the lander's token may write refs/heads/*")
/// @yah:status(review)
/// @yah:at(2026-10-13T08:57:13Z)
/// @yah:assignee(agent:bundle-anthropic-miravel)
/// @yah:phase(P2)
/// @yah:parent(R978)
/// @yah:next("The token carries the ref prefixes it may write: QED gets refs/qed/**, relays get refs/relays/**, the lander gets refs/heads/* (W366 §5). Pick a claim or a scoped scope string and record the choice in W363 §5.")
/// @yah:next("auth.rs `authorize` returns the grant; today it returns only `sub` (→ REMOTE_USER). serve.rs passes the grant into the pre-receive hook's env, and `check_policy` refuses any RefUpdate outside it.")
/// @yah:next("Add refs/relays/** to `check_policy` with non-fast-forward allowed, since relay tips rewrite on refresh (W366 §7, W365 §7 item 1).")
/// @yah:next("Mint side: cloud_cheers::git_push_token takes the ref scope. Fix every caller: qed_build_context.rs and the lander.")
/// @yah:next("Roll fleet-git (the live x86 workload, R971-T8 bring-up), server first.")
/// @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p fleet-git")
/// @yah:gotcha("Roll order: decide what a token with no ref grant admits while the camp binary is older than the server. Remove that allowance in this relay once the camp is upgraded (pre-1.0 rule: no permanent fallback).")
/// @yah:gotcha("W365's relay files the refs/relays/** GC exemption (sweep.rs / journal.rs) as a dependent of this ticket.")
/// @yah:gotcha("cloud_cheers.rs, qed_build_context.rs and yah_scopes.rs had uncommitted, unattributed working-tree edits on 2026-10-12. Re-read them before editing.")
/// @yah:files(oss/yubaba/crates/fleet-git/src/hook.rs)
/// @yah:files(oss/yubaba/crates/fleet-git/src/auth.rs)
/// @yah:files(oss/yubaba/crates/fleet-git/src/serve.rs)
/// @yah:files(app/yah/cli/src/cloud_cheers.rs)
/// @yah:files(app/yah/cli/src/qed_build_context.rs)
/// @yah:files(app/yah/cli/src/lander.rs)
/// @yah:files(oss/cheers/crates/cheers-core/src/yah_scopes.rs)
/// @yah:gotcha("Sequenced after R978-F2 by the leader (2026-10-13): both touch cloud_cheers::git_push_token's call sites, and F4 must fix the lander's caller that F2 creates. The fleet-git roll is operator-run — the courier lands code + tests only.")
/// @yah:depends_on(R978-T1)
/// @yah:depends_on(R978-F2)
/// @yah:cleanup("Delete the no-ref-scope allowance in oss/yubaba/crates/fleet-git/src/auth.rs RefGrant::from_scopes (a git:write token with no git:write-* scope is admitted as refs/qed/** only, R978-F4 roll order) once the camp binary mints ref scopes: return the computed grant as is, and drop the legacy_tok assertions in tests/roundtrip.rs and auth.rs.")
/// @yah:handoff("Landed: fleet-git ref grant. Token scopes git:write-qed / git:write-relays / git:write-heads (new in cheers-core yah_scopes.rs; scope grammar has no '/' or '*', so a fixed three-class vocabulary rather than a prefix claim; recorded in W363 §5). auth.rs authorize returns Grant{sub, refs: RefGrant}; serve.rs -> cgi.rs sets $FLEET_GIT_REFS on http-backend (env cleared, client cannot set it); hook.rs HookRequest.grant -> check_policy(u, grant, is_ancestor) refuses any RefUpdate outside the grant; refs/relays/** allows non-ff and delete; refs/heads/* and tags need heads and stay ff-only. A git:write token with no ref scope is admitted as refs/qed/** only (marked R978-F4 in auth.rs; @yah:cleanup filed).")
/// @yah:handoff("Mint side: cloud_cheers::GitRefScope {Qed,Relays,Heads}; git_push_token(repo, sub, refs). Callers: qed_build_context.rs (Qed, both sites), lander/mod.rs GitRemote::fleet (Heads; lander.rs is now lander/mod.rs), cloud_cheers git_exec (Heads, operator tool).")
/// @yah:handoff("ROLL STEPS (operator-run, nothing rolled by this ticket): 1) build + roll the fleet-git workload (server) first; the new server still admits old no-ref-scope QED tokens as refs/qed/**. 2) only then install the new camp binary (yah-install / yah-desktop-build + relaunch) so QED mints git:write-qed and the lander mints git:write-heads. 3) after the camp is upgraded, work the @yah:cleanup to delete the no-grant allowance. Do not upgrade the camp before the server: whether the old verifier tolerates unfamiliar git:write-* scopes was not checked. Also: until step 2 the lander's old token (no heads scope) is refused on refs/heads/camp.")
/// @yah:verify("cargo test --manifest-path oss/yubaba/Cargo.toml -p fleet-git: 29 passed, 0 failed (20 unit incl. new policy/auth-grant tests, 8 roundtrip incl. legacy-token and relays non-ff pushes, 1 tail_cost)")
/// @yah:verify("cargo check -p yah NOT verified: blocked by a peer's in-flight cloud-client error (lib.rs:2611/2625 unresolved base64); re-run it once that is fixed. cargo test -p cheers-core (scope count 20->23) not run.")
/// @yah:gotcha("lander call site edited at app/yah/cli/src/lander/mod.rs:120 only; peer courier R978-F2/F6 owns that file.")
/// @yah:handoff("ROLL ORDER: camp may upgrade BEFORE the server. Deployed fleet-git auth (git show 42ae52f0:oss/yubaba/crates/fleet-git/src/auth.rs:86-90) only checks claims.scope.contains(GIT_READ) / contains(GIT_WRITE); extra scopes are ignored. Token decode (oss/cheers/crates/cheers-verify/src/public_verifier.rs:134-160, McpClaims serde) deserializes scope as Vec<Scope>, and Scope::from_str (cheers-core/src/scope.rs:116-124) rejects only wildcards/malformed strings, not unregistered ones, so git:write-heads does not fail verification. CAVEAT: a token carrying ONLY git:write-heads (no git:write) is 403 on push at the old server (auth.rs:89), so the mint side must keep emitting git:write alongside until the server is upgraded.")
/// @yah:verify("cargo test -p cheers-core (oss/cheers workspace): 147 + 2 passed, 0 failed, no count/list expectation changes needed.")
/// @yah:gotcha("cargo check -p yah is red only on peer file crates/yah/cloud-client/src/lib.rs:2611/2625 (unresolved base64 import, E0432/E0433); no errors seen in cloud_cheers.rs, qed_build_context.rs or lander/. Not touched.")
/// @yah:verify("Miravel/libra: `cargo check -p yah` EXIT=0 (green). cloud_cheers::git_push_token_with already mints [GIT_READ, GIT_WRITE, refs.scope()] (cloud_cheers.rs:575; git_attach_token at :615 likewise) and the test at :858 asserts GIT_WRITE present; no change needed for the old fleet-git server's git:write check.")
pub fn check_policy(
    u: &RefUpdate,
    grant: RefGrant,
    is_ancestor: impl Fn(&str, &str) -> Result<bool>,
) -> std::result::Result<(), String> {
    let r = &u.refname;
    // R997-B18: pre-receive runs before git checks the name, and an accepted
    // update is journalled; a name git would refuse must never reach the journal.
    if !valid_refname(r) {
        return Err(format!("{r:?}: not a valid refname"));
    }
    if r.starts_with("refs/qed/") {
        return if grant.qed { Ok(()) } else { Err(format!("{r}: this token may not write refs/qed/**")) };
    }
    if r.starts_with("refs/relays/") {
        return if grant.relays { Ok(()) } else { Err(format!("{r}: this token may not write refs/relays/**")) };
    }
    // R975-F22 (W368 §7): a handover park is ephemeral — re-parked over, then
    // deleted by the incoming host — so non-fast-forward and delete are allowed.
    // `authorize` admits the grant only with a camp-bound `git_ref` claim, which
    // `check_ref_claim` has already held this update to.
    if r.starts_with(crate::auth::CAMP_HOST_PREFIX) {
        return if grant.camp_host {
            Ok(())
        } else {
            Err(format!("{r}: this token may not write refs/camp-host/**"))
        };
    }
    if !(r.starts_with("refs/heads/") || r.starts_with("refs/tags/")) {
        return Err(format!(
            "{r}: only refs/heads/*, refs/tags/*, refs/qed/**, refs/relays/** and refs/camp-host/** are accepted"
        ));
    }
    if !grant.heads {
        return Err(format!("{r}: this token may not write refs/heads/* or refs/tags/*"));
    }
    if is_zero(&u.new) {
        return Err(format!("{r}: branches and tags are never deleted here"));
    }
    if is_zero(&u.old) {
        return Ok(());
    }
    match is_ancestor(&u.old, &u.new) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("{r}: not a fast-forward (force-pushes are refused)")),
        Err(e) => Err(format!("{r}: could not check ancestry: {e:#}")),
    }
}

/// git's `check-ref-format` rules for a full refname (`refs/...`, no
/// `--allow-onelevel`, no `--refspec-pattern`): every name this accepts is one
/// `git update-ref` accepts, so a journalled update always replays.
pub fn valid_refname(r: &str) -> bool {
    if !r.starts_with("refs/") || r.ends_with('/') || r.ends_with('.') || r == "@" {
        return false;
    }
    if r.contains("..") || r.contains("@{") {
        return false;
    }
    if r.bytes().any(|b| b < 0x20 || b == 0x7f || matches!(b, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')) {
        return false;
    }
    r.split('/').all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"))
}

// ---------------------------------------------------------------- server side

/// The supervisor's half: listens on the hook socket.
pub struct HookServer {
    pub root: PathBuf,
    pub git: PathBuf,
    pub fence: Arc<Fence>,
    pub log: Arc<dyn PushLog>,
}

impl HookServer {
    pub async fn serve(self: Arc<Self>, listener: tokio::net::UnixListener) {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = me.connection(stream).await {
                    tracing::warn!(error = %e, "hook connection failed");
                }
            });
        }
    }

    async fn connection(&self, stream: tokio::net::UnixStream) -> Result<()> {
        let (rd, mut wr) = stream.into_split();
        let mut line = String::new();
        tokio::io::BufReader::new(rd).read_line(&mut line).await?;
        let reply = match serde_json::from_str::<HookRequest>(&line) {
            Ok(req) => self.handle(req).await,
            Err(e) => HookReply { ok: false, message: format!("fleet-git: bad hook request: {e}") },
        };
        let mut out = serde_json::to_string(&reply)?;
        out.push('\n');
        wr.write_all(out.as_bytes()).await?;
        Ok(())
    }

    pub async fn handle(&self, req: HookRequest) -> HookReply {
        match self.handle_inner(req).await {
            Ok(()) => HookReply { ok: true, message: String::new() },
            Err(msg) => HookReply { ok: false, message: format!("fleet-git: {msg}") },
        }
    }

    async fn handle_inner(&self, req: HookRequest) -> std::result::Result<(), String> {
        let root = self.root.canonicalize().map_err(|e| e.to_string())?;
        let repo = repo::name_of(&root, &req.repo_dir)
            .ok_or_else(|| format!("{} is not a repo this server owns", req.repo_dir.display()))?;
        let grant = req.grant;
        let only = req.only;
        let push = AcceptedPush {
            repo,
            repo_dir: req.repo_dir,
            quarantine: req.quarantine,
            pusher: req.pusher,
            updates: req.updates,
            epoch: self.fence.epoch(),
        };
        match req.stage {
            Stage::PreReceive => {
                let git = self.git.clone();
                let p = push.clone();
                tokio::task::spawn_blocking(move || policy_all(&git, &p, grant, only.as_deref()))
                    .await
                    .map_err(|e| e.to_string())??;
                match self.fence.check().await {
                    FenceCheck::Holds => {}
                    FenceCheck::Lost(lost) => {
                        return Err(format!("this server no longer holds the writer claim ({lost}); retry"))
                    }
                    FenceCheck::Unknown(e) => {
                        return Err(format!("could not confirm the writer claim ({e:#}); retry"))
                    }
                }
                self.log.append(&push).await.map_err(|e| format!("durable log append failed: {e:#}"))
            }
            Stage::PostReceive => {
                self.log.committed(&push).await.map_err(|e| format!("post-receive failed: {e:#}"))
            }
        }
    }
}

/// The `git_ref` claim beside [`RefGrant`] (R969-T12): a token carrying one may
/// update, create or delete only that ref — an exact refname, or any ref under
/// it when the claim ends in `/`. It only narrows: [`check_policy`] still runs.
pub fn check_ref_claim(u: &RefUpdate, only: Option<&str>) -> std::result::Result<(), String> {
    let Some(only) = only else { return Ok(()) };
    let r = &u.refname;
    let allowed = if only.ends_with('/') { r.starts_with(only) } else { r == only };
    if allowed {
        Ok(())
    } else {
        Err(format!("{r}: this token may write only {only}"))
    }
}

fn policy_all(
    git: &Path,
    push: &AcceptedPush,
    grant: RefGrant,
    only: Option<&str>,
) -> std::result::Result<(), String> {
    let mut errors = Vec::new();
    for u in &push.updates {
        // Each `old` must equal our view of the ref (W363 §2 step 1).
        match current_ref(git, &push.repo_dir, &u.refname) {
            Ok(None) if is_zero(&u.old) => {}
            Ok(Some(cur)) if cur == u.old => {}
            Ok(cur) => {
                let have = cur.unwrap_or_else(|| "nothing".into());
                errors.push(format!("{}: expected {} but the server has {have}", u.refname, u.old));
                continue;
            }
            Err(e) => {
                errors.push(format!("{}: {e:#}", u.refname));
                continue;
            }
        }
        if let Err(e) = check_ref_claim(u, only) {
            errors.push(e);
            continue;
        }
        if let Err(e) = check_policy(u, grant, |old, new| is_ancestor(git, push, old, new)) {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\nfleet-git: "))
    }
}

/// A ref's current oid (unpeeled, as receive-pack reports `old`), or `None`.
fn current_ref(git: &Path, repo_dir: &Path, refname: &str) -> Result<Option<String>> {
    let out = Command::new(git)
        .args(["rev-parse", "--verify", "--quiet", refname])
        .env("GIT_DIR", repo_dir)
        .output()?;
    Ok(out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

fn is_ancestor(git: &Path, push: &AcceptedPush, old: &str, new: &str) -> Result<bool> {
    let mut cmd = Command::new(git);
    cmd.args(["merge-base", "--is-ancestor", old, new]).env("GIT_DIR", &push.repo_dir);
    if let Some(q) = &push.quarantine {
        // Read the push's objects where receive-pack is holding them.
        cmd.env("GIT_OBJECT_DIRECTORY", q)
            .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", push.repo_dir.join("objects"));
    }
    let status = cmd.status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("git merge-base exited {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(old: &str, new: &str, r: &str) -> RefUpdate {
        RefUpdate { old: old.into(), new: new.into(), refname: r.into() }
    }
    const Z: &str = "0000000000000000000000000000000000000000";
    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";

    const ALL: RefGrant = RefGrant { qed: true, relays: true, heads: true, camp_host: true };
    const QED_ONLY: RefGrant = RefGrant { qed: true, ..RefGrant::NONE };
    const RELAYS_ONLY: RefGrant = RefGrant { relays: true, ..RefGrant::NONE };
    const CAMP_HOST_ONLY: RefGrant = RefGrant { camp_host: true, ..RefGrant::NONE };

    #[test]
    fn invalid_refnames_are_refused_before_the_journal() {
        for ok in ["refs/heads/main", "refs/relays/R1/tip", "refs/qed/run/a-b_c.d", "refs/tags/v1.0"] {
            assert!(valid_refname(ok), "{ok}");
            assert!(check_policy(&up(Z, A, ok), ALL, |_: &str, _: &str| Ok(true)).is_ok(), "{ok}");
        }
        for bad in [
            "refs/relays/R1/x.lock",
            "refs/relays/R1/a..b",
            "refs/relays/R1//b",
            "refs/relays/R1/.hidden",
            "refs/relays/R1/",
            "refs/relays/R1/x.",
            "refs/relays/R1/a@{b",
            "refs/relays/R1/a b",
            "refs/relays/R1/a\x01b",
            "refs/relays/R1/a~1",
            "refs/relays/R1/a:b",
            "refs/relays/R1/a*",
            "refs/relays/R1/a\\b",
            "HEAD",
        ] {
            assert!(!valid_refname(bad), "{bad:?}");
            assert!(check_policy(&up(Z, A, bad), ALL, |_: &str, _: &str| Ok(true)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn policy_matrix() {
        let ff = |_: &str, _: &str| Ok(true);
        let non_ff = |_: &str, _: &str| Ok(false);
        assert!(check_policy(&up(Z, A, "refs/heads/main"), ALL, non_ff).is_ok());
        assert!(check_policy(&up(A, B, "refs/heads/main"), ALL, ff).is_ok());
        assert!(check_policy(&up(A, B, "refs/heads/main"), ALL, non_ff).is_err());
        assert!(check_policy(&up(A, Z, "refs/heads/main"), ALL, ff).is_err());
        assert!(check_policy(&up(A, Z, "refs/tags/v1"), ALL, ff).is_err());
        assert!(check_policy(&up(A, B, "refs/tags/v1"), ALL, non_ff).is_err());
        assert!(check_policy(&up(A, B, "refs/qed/run/1"), ALL, non_ff).is_ok());
        assert!(check_policy(&up(A, Z, "refs/qed/run/1"), ALL, non_ff).is_ok());
        assert!(check_policy(&up(Z, A, "refs/notes/commits"), ALL, ff).is_err());
        assert!(check_policy(&up(Z, A, "refs/heads"), ALL, ff).is_err());
    }

    #[test]
    fn relays_namespace_allows_non_ff() {
        let non_ff = |_: &str, _: &str| Ok(false);
        assert!(check_policy(&up(A, B, "refs/relays/R978/tip"), RELAYS_ONLY, non_ff).is_ok());
        assert!(check_policy(&up(Z, A, "refs/relays/R978/tip"), RELAYS_ONLY, non_ff).is_ok());
        assert!(check_policy(&up(A, Z, "refs/relays/R978/tip"), RELAYS_ONLY, non_ff).is_ok());
    }

    #[test]
    fn updates_outside_the_grant_are_refused() {
        let ff = |_: &str, _: &str| Ok(true);
        // refs/heads needs `heads`: qed-only and relays-only tokens cannot move camp.
        for g in [QED_ONLY, RELAYS_ONLY, RefGrant::NONE] {
            assert!(check_policy(&up(A, B, "refs/heads/camp"), g, ff).is_err());
            assert!(check_policy(&up(Z, A, "refs/heads/main"), g, ff).is_err());
            assert!(check_policy(&up(Z, A, "refs/tags/v1"), g, ff).is_err());
        }
        assert!(check_policy(&up(A, B, "refs/qed/run/1"), RELAYS_ONLY, ff).is_err());
        assert!(check_policy(&up(A, B, "refs/relays/R1/tip"), QED_ONLY, ff).is_err());
        assert!(check_policy(&up(Z, A, "refs/qed/run/1"), RefGrant::NONE, ff).is_err());
        for g in [QED_ONLY, RELAYS_ONLY, RefGrant { heads: true, ..RefGrant::NONE }, RefGrant::NONE] {
            assert!(check_policy(&up(Z, A, "refs/camp-host/c1/park"), g, ff).is_err());
        }
    }

    /// R975-F22: the park token (camp-host grant + its camp's `git_ref`
    /// claim, as `policy_all` applies them) writes its own camp's park —
    /// create, re-park over it, delete — and nothing else: not refs/heads/*,
    /// not refs/qed/**, not another camp's park.
    #[test]
    fn camp_host_grant_writes_only_its_own_camps_park() {
        let non_ff = |_: &str, _: &str| Ok(false);
        let claim = Some("refs/camp-host/c1/");
        let both = |u: &RefUpdate| check_ref_claim(u, claim).and_then(|()| check_policy(u, CAMP_HOST_ONLY, non_ff));
        assert!(both(&up(Z, A, "refs/camp-host/c1/park")).is_ok());
        assert!(both(&up(A, B, "refs/camp-host/c1/park")).is_ok(), "re-parking is a non-ff overwrite");
        assert!(both(&up(B, Z, "refs/camp-host/c1/park")).is_ok(), "the incoming host deletes it");
        for refused in ["refs/camp-host/c2/park", "refs/camp-host/c10/park", "refs/heads/camp", "refs/heads/main",
            "refs/tags/v1", "refs/qed/run/1", "refs/relays/R1/tip"]
        {
            assert!(both(&up(Z, A, refused)).is_err(), "{refused} was admitted");
        }
        // The grant alone (no claim) still refuses every other family.
        for refused in ["refs/heads/camp", "refs/qed/run/1", "refs/relays/R1/tip", "refs/notes/x"] {
            assert!(check_policy(&up(Z, A, refused), CAMP_HOST_ONLY, non_ff).is_err(), "{refused}");
        }
    }

    #[test]
    fn ref_claim_confines_the_token() {
        let ret = Some("refs/qed/run-1/build.return");
        assert!(check_ref_claim(&up(Z, A, "refs/qed/run-1/build.return"), ret).is_ok());
        assert!(check_ref_claim(&up(A, Z, "refs/qed/run-1/build.return"), ret).is_ok());
        assert!(check_ref_claim(&up(A, B, "refs/qed/run-2/build"), ret).is_err());
        assert!(check_ref_claim(&up(A, B, "refs/qed/run-1/build"), ret).is_err());
        assert!(check_ref_claim(&up(A, B, "refs/qed/run-1/build.return.x"), ret).is_err());
        let prefix = Some("refs/relays/R1/");
        assert!(check_ref_claim(&up(A, B, "refs/relays/R1/tip"), prefix).is_ok());
        assert!(check_ref_claim(&up(A, B, "refs/relays/R10/tip"), prefix).is_err());
        assert!(check_ref_claim(&up(A, B, "refs/heads/main"), None).is_ok());
    }

    #[test]
    fn parses_hook_lines() {
        assert_eq!(parse_update(&format!("{Z} {A} refs/heads/main")).unwrap(), up(Z, A, "refs/heads/main"));
        assert!(parse_update("x y").is_err());
        assert!(is_zero(Z) && !is_zero(A) && !is_zero(""));
    }
}
