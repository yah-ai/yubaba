//! End to end against this host's system git (on the camp Mac: Apple git, not
//! Alpine's): push, clone, ref policy, and the fence — a second instance that
//! acquires the claim makes the first refuse pushes and shut down.

use fleet_git::auth::GitAuth;
use fleet_git::fence::Fence;
use fleet_git::hydrate::{self, Mode, RepoReport, Startup};
use fleet_git::serve::{serve, PushLocks, ServeConfig, ServeExit};
use fleet_git::stream::R2Log;
use object_store::memory::InMemory;
use object_store::ObjectStore;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;
use store_claim::BackupTarget;

struct Issuer(AsymmetricKeyPair<V4>);

impl Issuer {
    fn public(&self) -> [u8; 32] {
        self.0.public.as_bytes().try_into().unwrap()
    }
    fn token(&self, aud: &str, scopes: &[&str]) -> String {
        self.token_for_ref(aud, scopes, None)
    }
    /// R969-T12: `git_ref` is the claim confining a push to one ref.
    fn token_for_ref(&self, aud: &str, scopes: &[&str], git_ref: Option<&str>) -> String {
        let exp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 300;
        let mut payload = serde_json::json!({
            "iss": "yah-camp", "aud": aud, "sub": "user:tester", "iat": 0, "exp": exp,
            "jti": "t", "scope": scopes,
        });
        if let Some(r) = git_ref {
            payload["git_ref"] = r.into();
        }
        let footer = serde_json::json!({ "kid": cheers_verify::kid_for(&self.public()) });
        pasetors::version4::PublicToken::sign(
            &self.0.secret,
            payload.to_string().as_bytes(),
            Some(footer.to_string().as_bytes()),
            None,
        )
        .unwrap()
    }
}

struct Instance {
    url: String,
    task: tokio::task::JoinHandle<anyhow::Result<ServeExit>>,
    log: Arc<R2Log>,
    locks: Arc<PushLocks>,
    root: PathBuf,
    reports: Vec<RepoReport>,
}

async fn start(dir: &Path, name: &str, store: &Arc<dyn ObjectStore>, issuer: &Issuer) -> Instance {
    let target = BackupTarget { store: Arc::clone(store), prefix: String::new() };
    let owner = format!("fleet-git@{name}");
    let fence = Fence::establish(target, &owner).await.unwrap();
    let git_install = fleet_git::gitbin::probe().unwrap();
    let root = dir.join(name);
    let hook_exe = PathBuf::from(env!("CARGO_BIN_EXE_fleet-git"));
    let reports = match hydrate::startup(
        &BackupTarget { store: Arc::clone(store), prefix: String::new() },
        &fence,
        &git_install,
        &root,
        &hook_exe,
    )
    .await
    .unwrap()
    {
        Startup::Ready(r) => r,
        Startup::Superseded(why) => panic!("superseded during startup: {why}"),
    };
    let log = Arc::new(R2Log::new(
        BackupTarget { store: Arc::clone(store), prefix: String::new() },
        Arc::clone(&fence),
        &owner,
        git_install.git.clone(),
    ));
    let locks = Arc::new(PushLocks::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let cfg = ServeConfig {
        root: root.clone(),
        hook_sock: dir.join(format!("{name}.sock")),
        hook_exe,
        git: git_install,
        auth: GitAuth::from_public_key(&issuer.public(), "yah-camp").unwrap(),
        // Long: this test drives fence loss through the push path, not the timer.
        fence_period: Duration::from_secs(3600),
        locks: Arc::clone(&locks),
    };
    let task = tokio::spawn(serve(cfg, fence, Arc::clone(&log) as _, listener, std::future::pending()));
    Instance { url, task, log, locks, root, reports }
}

fn git(dir: &Path, home: &Path, token: Option<&str>, args: &[&str]) -> Output {
    let mut c = Command::new("git");
    c.args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid");
    if let Some(t) = token {
        c.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.extraHeader")
            .env("GIT_CONFIG_VALUE_0", format!("Authorization: Bearer {t}"));
    }
    c.output().unwrap()
}

fn ok(o: Output) -> String {
    assert!(o.status.success(), "git failed: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn commit(work: &Path, home: &Path, msg: &str) -> String {
    std::fs::write(work.join("f.txt"), msg).unwrap();
    ok(git(work, home, None, &["add", "f.txt"]));
    ok(git(work, home, None, &["commit", "-q", "-m", msg]));
    ok(git(work, home, None, &["rev-parse", "HEAD"]))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_clone_policy_and_fence() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let issuer = Issuer(AsymmetricKeyPair::<V4>::generate().unwrap());
    let push_tok = issuer.token("fleet-git/yah", &["git:read", "git:write", "git:write-qed", "git:write-relays", "git:write-heads"]);
    let read_tok = issuer.token("fleet-git/yah", &["git:read"]);
    let legacy_tok = issuer.token("fleet-git/yah", &["git:read", "git:write"]);
    let relays_tok = issuer.token("fleet-git/yah", &["git:read", "git:write", "git:write-relays"]);
    let attach_tok = issuer.token_for_ref(
        "fleet-git/yah",
        &["git:read", "git:write", "git:write-qed"],
        Some("refs/qed/run-9/build.return"),
    );
    // R979-T2: the relay release at archive deletes refs/relays/<R>/{base,tip}
    // under that relay's claim, never a broad delete credential.
    let relay_scopes = ["git:read", "git:write", "git:write-relays"];
    let r1_tok = issuer.token_for_ref("fleet-git/yah", &relay_scopes, Some("refs/relays/R1/"));
    let r2_tok = issuer.token_for_ref("fleet-git/yah", &relay_scopes, Some("refs/relays/R2/"));
    // R975-F22: a handover park token is bound to one camp's refs/camp-host/<id>/.
    let park_scopes = ["git:read", "git:write", "git:write-camp-host"];
    let c1_tok = issuer.token_for_ref("fleet-git/yah", &park_scopes, Some("refs/camp-host/c1/"));
    let unbound_tok = issuer.token("fleet-git/yah", &park_scopes);
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

    let a = start(tmp.path(), "a", &store, &issuer).await;
    let a_url = format!("{}/yah.git", a.url);
    let w = work.clone();
    let h = home.clone();
    let (tip, a_url) = tokio::task::spawn_blocking(move || {
        ok(git(&w, &h, None, &["init", "-q", "-b", "main"]));
        let tip = commit(&w, &h, "one");

        // No token, then a read-only token: both refused.
        assert!(!git(&w, &h, None, &["push", &a_url, "main"]).status.success());
        assert!(!git(&w, &h, Some(&read_tok), &["push", &a_url, "main"]).status.success());

        ok(git(&w, &h, Some(&push_tok), &["push", "-q", &a_url, "main"]));
        let clone = w.parent().unwrap().join("clone");
        ok(git(w.parent().unwrap(), &h, Some(&read_tok), &["clone", "-q", &a_url, clone.to_str().unwrap()]));
        assert_eq!(ok(git(&clone, &h, None, &["rev-parse", "HEAD"])), tip);

        // Policy: no force-push, no branch delete, no foreign namespace; refs/qed is free.
        let tip2 = commit(&w, &h, "two");
        ok(git(&w, &h, Some(&push_tok), &["push", "-q", &a_url, "main"]));
        ok(git(&w, &h, None, &["reset", "-q", "--hard", &tip]));
        let side = commit(&w, &h, "side");
        assert!(!git(&w, &h, Some(&push_tok), &["push", "-f", &a_url, "main"]).status.success());
        assert!(!git(&w, &h, Some(&push_tok), &["push", &a_url, ":main"]).status.success());
        assert!(!git(&w, &h, Some(&push_tok), &["push", &a_url, "HEAD:refs/notes/x"]).status.success());
        ok(git(&w, &h, Some(&push_tok), &["push", "-q", &a_url, "HEAD:refs/qed/run-1"]));
        ok(git(&w, &h, Some(&push_tok), &["push", "-q", "-f", &a_url, &format!("{tip2}:refs/qed/run-1")]));
        ok(git(&w, &h, Some(&push_tok), &["push", "-q", &a_url, ":refs/qed/run-1"]));

        // R978-F4: ref grants. A token with no ref scope is the roll-order
        // allowance (refs/qed/** only); a relays token moves refs/relays/**
        // non-ff but not refs/heads/*.
        assert!(!git(&w, &h, Some(&legacy_tok), &["push", &a_url, "HEAD:refs/heads/camp"]).status.success());
        assert!(!git(&w, &h, Some(&legacy_tok), &["push", &a_url, "HEAD:refs/relays/R1/tip"]).status.success());
        ok(git(&w, &h, Some(&legacy_tok), &["push", "-q", &a_url, "HEAD:refs/qed/run-2"]));
        assert!(!git(&w, &h, Some(&relays_tok), &["push", &a_url, "HEAD:refs/heads/camp"]).status.success());
        assert!(!git(&w, &h, Some(&relays_tok), &["push", &a_url, "HEAD:refs/qed/run-3"]).status.success());
        ok(git(&w, &h, Some(&relays_tok), &["push", "-q", &a_url, &format!("{tip2}:refs/relays/R1/tip")]));
        ok(git(&w, &h, Some(&relays_tok), &["push", "-q", "-f", &a_url, "HEAD:refs/relays/R1/tip"]));
        ok(git(&w, &h, Some(&relays_tok), &["push", "-q", &a_url, &format!("{tip2}:refs/relays/R1/base")]));

        // R979-T2: R2's claim cannot delete R1's refs, nor can a read token;
        // R1's own claim deletes both.
        for r in [":refs/relays/R1/tip", ":refs/relays/R1/base"] {
            assert!(!git(&w, &h, Some(&r2_tok), &["push", &a_url, r]).status.success());
            assert!(!git(&w, &h, Some(&read_tok), &["push", &a_url, r]).status.success());
        }
        assert!(!ok(git(&w, &h, Some(&read_tok), &["ls-remote", &a_url, "refs/relays/R1/*"])).is_empty());
        ok(git(&w, &h, Some(&r1_tok), &["push", "-q", &a_url, ":refs/relays/R1/tip", ":refs/relays/R1/base"]));
        assert_eq!(ok(git(&w, &h, Some(&read_tok), &["ls-remote", &a_url, "refs/relays/R1/*"])), "");

        // R975-F22: a handover park token, bound to camp c1. It parks, re-parks
        // over the park (non-ff) and deletes it; it cannot touch c2's park, the
        // lander's refs/heads/*, or refs/qed/**. Unbound, the scope is refused.
        ok(git(&w, &h, Some(&c1_tok), &["push", "-q", &a_url, &format!("{tip2}:refs/camp-host/c1/park")]));
        ok(git(&w, &h, Some(&c1_tok), &["push", "-q", "-f", &a_url, "HEAD:refs/camp-host/c1/park"]));
        for refused in ["HEAD:refs/camp-host/c2/park", "HEAD:refs/heads/camp", "HEAD:refs/qed/run-4"] {
            assert!(!git(&w, &h, Some(&c1_tok), &["push", &a_url, refused]).status.success(), "{refused}");
        }
        assert!(!git(&w, &h, Some(&unbound_tok), &["push", &a_url, "HEAD:refs/camp-host/c1/park2"]).status.success());
        assert!(!git(&w, &h, Some(&push_tok), &["push", &a_url, ":refs/camp-host/c1/park"]).status.success());
        ok(git(&w, &h, Some(&c1_tok), &["push", "-q", &a_url, ":refs/camp-host/c1/park"]));
        assert_eq!(ok(git(&w, &h, Some(&read_tok), &["ls-remote", &a_url, "refs/camp-host/*"])), "");

        // R969-T12: a qed.attach token confined to its return ref writes that
        // ref (create, force, delete) and nothing else under refs/qed/**.
        ok(git(&w, &h, Some(&push_tok), &["push", "-q", &a_url, "HEAD:refs/qed/run-8/build"]));
        assert!(!git(&w, &h, Some(&attach_tok), &["push", "-f", &a_url, &format!("{tip2}:refs/qed/run-8/build")]).status.success());
        assert!(!git(&w, &h, Some(&attach_tok), &["push", &a_url, ":refs/qed/run-8/build"]).status.success());
        assert!(!git(&w, &h, Some(&attach_tok), &["push", &a_url, "HEAD:refs/qed/run-9/build"]).status.success());
        ok(git(&w, &h, Some(&attach_tok), &["push", "-q", &a_url, "HEAD:refs/qed/run-9/build.return"]));
        ok(git(&w, &h, Some(&attach_tok), &["push", "-q", "-f", &a_url, &format!("{tip2}:refs/qed/run-9/build.return")]));
        ok(git(&w, &h, Some(&attach_tok), &["push", "-q", &a_url, ":refs/qed/run-9/build.return"]));
        let _ = side;
        ok(git(&w, &h, None, &["reset", "-q", "--hard", &tip2]));
        let remote = ok(git(&w, &h, Some(&read_tok), &["ls-remote", &a_url, "refs/heads/main"]));
        assert!(remote.starts_with(&tip2), "{remote}");
        (tip2, a_url)
    })
    .await
    .unwrap();

    // A second instance takes the claim. A must refuse the next push and exit.
    // B starts on an empty volume and rehydrates A's `yah` from the store.
    let b = start(tmp.path(), "b", &store, &issuer).await;
    assert_eq!(b.reports.len(), 1);
    assert_eq!((b.reports[0].mode, b.reports[0].seq), (Mode::Cold, journal::head(&b.log.target, "yah").await.unwrap()));
    let b_url = format!("{}/yah.git", b.url);
    let w = work.clone();
    let h = home.clone();
    let b_tok = issuer.token("fleet-git/yah", &["git:read", "git:write", "git:write-qed", "git:write-relays", "git:write-heads"]);
    let push_tok = b_tok.clone();
    tokio::task::spawn_blocking(move || {
        let restored = ok(git(&w, &h, Some(&b_tok), &["ls-remote", &b_url, "refs/heads/main"]));
        assert!(restored.starts_with(&tip), "B restored main at A's journal head: {restored}");
        let three = commit(&w, &h, "three");
        let refused = git(&w, &h, Some(&push_tok), &["push", &a_url, "main"]);
        assert!(!refused.status.success(), "the fenced instance accepted a push");
        let err = String::from_utf8_lossy(&refused.stderr);
        assert!(err.contains("writer claim"), "{err}");
        // B, holding the claim, takes the same history.
        ok(git(&w, &h, Some(&b_tok), &["push", "-q", &b_url, "main"]));
        let remote = ok(git(&w, &h, Some(&b_tok), &["ls-remote", &b_url, "refs/heads/main"]));
        assert!(remote.starts_with(&three), "{remote}");
        let _ = tip;
    })
    .await
    .unwrap();

    let exit = tokio::time::timeout(Duration::from_secs(10), a.task).await.unwrap().unwrap().unwrap();
    assert!(matches!(exit, ServeExit::FenceLost(_)), "{exit:?}");
    assert!(!b.task.is_finished());
}

// ---------------------------------------------------------------- R971-F3: the R2 log

use fleet_git::journal;
use fleet_git::stream::{read_marker, unapplied, FailPoint};
use futures_util::TryStreamExt;

/// Object keys under `repos/<repo>/<sub>`, sorted.
async fn keys(store: &Arc<dyn ObjectStore>, repo: &str, sub: &str) -> Vec<String> {
    let p = object_store::path::Path::from(format!("repos/{repo}/{sub}"));
    let mut v: Vec<String> = store.list(Some(&p)).map_ok(|m| m.location.to_string()).try_collect().await.unwrap();
    v.sort();
    v
}

struct Rig {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    work: PathBuf,
    store: Arc<dyn ObjectStore>,
    a: Instance,
    url: String,
    tok: String,
    /// Camp-bound to `refs/camp-host/c1/` (R975-F22's park token).
    park_tok: String,
}

async fn rig() -> Rig {
    rig_with_issuer().await.0
}

impl Rig {
    /// Commit `msg` and push `spec`; returns (new HEAD, push succeeded).
    async fn commit_push(&self, msg: &str, spec: &str) -> (String, bool) {
        let (w, h, t, u, s, m) =
            (self.work.clone(), self.home.clone(), self.tok.clone(), self.url.clone(), spec.to_string(), msg.to_string());
        tokio::task::spawn_blocking(move || {
            let tip = if m.is_empty() { ok(git(&w, &h, None, &["rev-parse", "HEAD"])) } else { commit(&w, &h, &m) };
            let pushed = git(&w, &h, Some(&t), &["push", "-q", &u, &s]).status.success();
            (tip, pushed)
        })
        .await
        .unwrap()
    }
    async fn remote(&self, r: &str) -> String {
        let (w, h, t, u, r) = (self.work.clone(), self.home.clone(), self.tok.clone(), self.url.clone(), r.to_string());
        tokio::task::spawn_blocking(move || ok(git(&w, &h, Some(&t), &["ls-remote", &u, &r]))).await.unwrap()
    }
    fn repo_dir(&self) -> PathBuf {
        self.a.root.join("yah.git")
    }
}

/// `GET /healthz` body over a bare socket (this crate has no HTTP client dep).
async fn healthz(base: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = base.trim_start_matches("http://");
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET /healthz HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes()).await.unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    assert!(raw.starts_with("HTTP/1.0 200") || raw.starts_with("HTTP/1.1 200"), "{raw}");
    raw.split_once("\r\n\r\n").unwrap().1.to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_pushes_leave_n_packs_and_n_entries() {
    let r = rig().await;
    for i in 1..=3 {
        assert!(r.commit_push(&format!("c{i}"), "main").await.1);
    }
    // Re-pushing what the remote has is a no-op: no hook, no pack, no entry.
    assert!(r.commit_push("", "main").await.1);
    assert_eq!(keys(&r.store, "yah", "packs").await.len(), 3);
    assert_eq!(keys(&r.store, "yah", "journal").await.len(), 3);
    // A ref pointed at an existing commit is journaled with no pack.
    assert!(r.commit_push("", "HEAD:refs/qed/run/step").await.1);
    assert_eq!(keys(&r.store, "yah", "packs").await.len(), 3);
    let e4 = journal::read(&r.a.log.target, "yah", 4).await.unwrap().unwrap();
    assert_eq!((e4.pack.as_deref(), e4.pusher.as_str(), e4.updates[0].refname.as_str()), (None, "user:tester", "refs/qed/run/step"));
    let e1 = journal::read(&r.a.log.target, "yah", 1).await.unwrap().unwrap();
    assert!(e1.pack.is_some() && e1.pack_bytes > 0 && e1.epoch == r.a.log.fence.epoch());
    assert_eq!(read_marker(&r.repo_dir()).unwrap().unwrap().seq, 4);
    // R978-T22: /healthz reports that position beside the epoch.
    let hz = healthz(&r.a.url).await;
    assert_eq!(hz, format!("ok epoch {}\njournal yah 4\n", r.a.log.fence.epoch()));
    assert!(unapplied(&r.a.log.target, "yah", &r.repo_dir()).await.unwrap().is_empty());

    // §6 GC: eight days on, the qed ref is deleted through the journal.
    let later = journal::now_ms() + 8 * 24 * 3600 * 1000;
    let seq = {
        let _g = r.a.locks.lock("yah").await;
        fleet_git::sweep::gc_ephemeral(&r.a.log, "yah", &r.repo_dir(), later, fleet_git::sweep::AGE_OUTS)
            .await
            .unwrap()
    };
    assert_eq!(seq, Some(5));
    let gc = journal::read(&r.a.log.target, "yah", 5).await.unwrap().unwrap();
    assert_eq!((gc.pusher.as_str(), gc.pack.as_deref()), (journal::GC_PUSHER, None));
    assert!(fleet_git::hook::is_zero(&gc.updates[0].new));
    assert_eq!(r.remote("refs/qed/run/step").await, "");
    assert!(!r.remote("refs/heads/main").await.is_empty(), "GC touched only refs/qed");
    assert_eq!(read_marker(&r.repo_dir()).unwrap().unwrap().seq, 5);
}

/// R979-T2 / W365 §7 item 1: a live relay's refs are never age-GC'd. Only the
/// camp's relay release deletes them. If the ephemeral GC is ever widened past
/// `refs/qed/`, this fails rather than silently reaping relay tips.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_refs_survive_the_ephemeral_gc() {
    let r = rig().await;
    assert!(r.commit_push("c1", "main").await.1);
    assert!(r.commit_push("", "HEAD:refs/relays/R1/base").await.1);
    assert!(r.commit_push("c2", "HEAD:refs/relays/R1/tip").await.1);
    assert!(r.commit_push("", "HEAD:refs/qed/run/step").await.1);
    let later = journal::now_ms() + 2 * fleet_git::sweep::EPHEMERAL_MAX_AGE.as_millis() as u64;
    let seq = {
        let _g = r.a.locks.lock("yah").await;
        fleet_git::sweep::gc_ephemeral(&r.a.log, "yah", &r.repo_dir(), later, fleet_git::sweep::AGE_OUTS)
            .await
            .unwrap()
    };
    assert!(seq.is_some(), "the qed ref aged out");
    assert_eq!(r.remote("refs/qed/run/step").await, "");
    assert!(!r.remote("refs/relays/R1/base").await.is_empty());
    assert!(!r.remote("refs/relays/R1/tip").await.is_empty());
}

/// R975-F23 (R975-F22 #1): a park nobody unparked ages out after
/// `PARK_MAX_AGE`, through the same journaled GC; it outlives a qed ref.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_park_ages_out_after_park_max_age() {
    use fleet_git::sweep::{gc_ephemeral, AGE_OUTS, PARK_MAX_AGE};
    let r = rig().await;
    assert!(r.commit_push("c1", "main").await.1);
    let (w, h, t, u) = (r.work.clone(), r.home.clone(), r.park_tok.clone(), r.url.clone());
    tokio::task::spawn_blocking(move || ok(git(&w, &h, Some(&t), &["push", "-q", &u, "HEAD:refs/camp-host/c1/park"])))
        .await
        .unwrap();
    async fn gc(r: &Rig, days: u64) -> Option<u64> {
        let later = journal::now_ms() + days * 24 * 3600 * 1000;
        let _g = r.a.locks.lock("yah").await;
        gc_ephemeral(&r.a.log, "yah", &r.repo_dir(), later, AGE_OUTS).await.unwrap()
    }
    assert_eq!(gc(&r, 8).await, None, "a week-old park is not abandoned yet");
    assert!(!r.remote("refs/camp-host/c1/park").await.is_empty());
    let days = PARK_MAX_AGE.as_secs() / (24 * 3600) + 1;
    assert!(gc(&r, days).await.is_some());
    assert_eq!(r.remote("refs/camp-host/c1/park").await, "");
    assert!(!r.remote("refs/heads/main").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crashes_leave_the_store_consistent() {
    let r = rig().await;
    let (one, pushed) = r.commit_push("one", "main").await;
    assert!(pushed);

    // Crash between the pack PUT and the journal Create: the push fails, an
    // unreferenced pack is left (the sweep's 1 h rule), the journal is untouched.
    r.a.log.inject(FailPoint::AfterPackPut);
    let (two, pushed) = r.commit_push("two", "main").await;
    assert!(!pushed);
    assert_eq!(keys(&r.store, "yah", "packs").await.len(), 2);
    assert_eq!(keys(&r.store, "yah", "journal").await.len(), 1);
    assert!(r.remote("refs/heads/main").await.starts_with(&one));
    // The next push succeeds and takes seq 2.
    assert!(r.commit_push("", "main").await.1);
    assert!(r.remote("refs/heads/main").await.starts_with(&two));
    assert_eq!(keys(&r.store, "yah", "journal").await.len(), 2);
    assert_eq!(read_marker(&r.repo_dir()).unwrap().unwrap().seq, 2);

    // Crash after the journal Create, before git moves the ref: the entry is
    // in R2, the ref is not moved, and the marker shows the volume is behind.
    r.a.log.inject(FailPoint::AfterJournalCreate);
    let (three, pushed) = r.commit_push("three", "main").await;
    assert!(!pushed);
    assert!(r.remote("refs/heads/main").await.starts_with(&two));
    assert_eq!(read_marker(&r.repo_dir()).unwrap().unwrap().seq, 2);
    let behind = unapplied(&r.a.log.target, "yah", &r.repo_dir()).await.unwrap();
    assert_eq!(behind.len(), 1);
    assert_eq!((behind[0].seq, behind[0].updates[0].new.as_str()), (3, three.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_writers_one_wins_the_loser_refuses() {
    use fleet_git::hook::{AcceptedPush, PushLog, RefUpdate};
    let tmp = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let gitbin = fleet_git::gitbin::probe().unwrap().git;
    let mut logs = Vec::new();
    for name in ["x", "y"] {
        let t = || BackupTarget { store: Arc::clone(&store), prefix: String::new() };
        let fence = Fence::establish(t(), &format!("fleet-git@{name}")).await.unwrap();
        let dir = tmp.path().join(name).join("yah.git");
        std::fs::create_dir_all(&dir).unwrap();
        logs.push((Arc::new(R2Log::new(t(), fence, name, gitbin.clone())), dir));
    }
    let push = |dir: &PathBuf, new: char| AcceptedPush {
        repo: "yah".into(),
        repo_dir: dir.clone(),
        quarantine: None,
        pusher: "user:t".into(),
        updates: vec![RefUpdate { old: "0".repeat(40), new: new.to_string().repeat(40), refname: "refs/qed/r/s".into() }],
        epoch: 1,
    };
    let (px, py) = (push(&logs[0].1, '1'), push(&logs[1].1, '2'));
    let (rx, ry) = tokio::join!(logs[0].0.append(&px), logs[1].0.append(&py));
    assert_eq!(rx.is_ok() as u8 + ry.is_ok() as u8, 1, "exactly one writer wins seq 1: {rx:?} {ry:?}");
    let (winner, loser, err) = if rx.is_ok() { (&logs[0].0, &logs[1].0, ry) } else { (&logs[1].0, &logs[0].0, rx) };
    assert!(format!("{:#}", err.unwrap_err()).contains("journal moved"));
    assert!(loser.fence.is_lost(), "the loser enters fence loss");
    assert!(!winner.fence.is_lost());
    assert_eq!(keys(&store, "yah", "journal").await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_then_sweep_leaves_the_retained_set() {
    use fleet_git::snapshot::{read_latest, take};
    let r = rig().await;
    let dir = r.repo_dir();
    let snap = || take(&r.a.log, &r.a.locks, "yah", &dir);
    assert!(r.commit_push("c1", "main").await.1);
    assert_eq!(snap().await.unwrap().unwrap().seq, 1);
    assert!(snap().await.unwrap().is_none(), "nothing new since seq 1");
    assert!(r.commit_push("c2", "main").await.1);
    assert!(r.commit_push("", "HEAD:refs/qed/a/b").await.1);
    assert_eq!(snap().await.unwrap().unwrap().seq, 3);
    let (tip, _) = r.commit_push("c4", "main").await;
    let s4 = snap().await.unwrap().unwrap();
    assert_eq!(s4.seq, 4);
    assert_eq!(read_latest(&r.a.log.target, "yah").await.unwrap().unwrap().0, s4);

    fleet_git::sweep::sweep(&r.a.log.target, "yah", journal::now_ms()).await.unwrap();
    let e4 = journal::read(&r.a.log.target, "yah", 4).await.unwrap().unwrap();
    assert_eq!(keys(&r.store, "yah", "journal").await, vec!["repos/yah/journal/0000000000000004.json"]);
    assert_eq!(keys(&r.store, "yah", "packs").await, vec![format!("repos/yah/packs/{}", e4.pack.unwrap())]);
    let snaps = keys(&r.store, "yah", "snapshots").await;
    assert_eq!(snaps.len(), 4, "{snaps:?}");
    assert!(snaps.iter().all(|k| k.contains("/0000000000000003/") || k.contains("/0000000000000004/")), "{snaps:?}");
    let refs3: serde_json::Value = serde_json::from_slice(
        &object_store::ObjectStoreExt::get(&*r.store, &object_store::path::Path::from("repos/yah/snapshots/0000000000000003/refs.json"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(refs3.as_array().unwrap().len(), 2, "{refs3}");

    // The local repack left a servable repo.
    assert!(r.remote("refs/heads/main").await.starts_with(&tip));
    let (w, h, t, u) = (r.work.clone(), r.home.clone(), r.tok.clone(), r.url.clone());
    tokio::task::spawn_blocking(move || {
        let c = w.parent().unwrap().join("clone2");
        ok(git(w.parent().unwrap(), &h, Some(&t), &["clone", "-q", &u, c.to_str().unwrap()]));
        assert_eq!(ok(git(&c, &h, None, &["rev-parse", "HEAD"])), tip);
    })
    .await
    .unwrap();
}

// ---------------------------------------------------------------- R971-F4: startup rehydrate

/// The refs the journal says a repo holds: every entry folded in order.
async fn journal_refs(t: &BackupTarget, repo: &str) -> Vec<(String, String)> {
    let mut m = std::collections::BTreeMap::new();
    for e in journal::entries_after(t, repo, 0).await.unwrap() {
        for u in e.updates {
            if fleet_git::hook::is_zero(&u.new) {
                m.remove(&u.refname);
            } else {
                m.insert(u.refname, u.new);
            }
        }
    }
    m.into_iter().map(|(r, o)| (o, r)).collect()
}

async fn disk_refs(dir: &Path) -> Vec<(String, String)> {
    let git = fleet_git::gitbin::probe().unwrap().git;
    let mut v = fleet_git::stream::for_each_ref(&git, dir, None).await.unwrap();
    v.sort_by(|a, b| a.1.cmp(&b.1));
    v
}

impl Rig {
    /// Stop A and start a new instance on the same volume.
    async fn restart(&mut self, issuer: &Issuer) {
        self.stop().await;
        let dir = self.a.root.parent().unwrap().to_path_buf();
        self.a = start(&dir, "a", &self.store, issuer).await;
        self.url = format!("{}/yah.git", self.a.url);
    }
    async fn stop(&mut self) {
        if !self.a.task.is_finished() {
            self.a.task.abort();
            let _ = (&mut self.a.task).await;
        }
    }
}

async fn rig_with_issuer() -> (Rig, Issuer) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let issuer = Issuer(AsymmetricKeyPair::<V4>::generate().unwrap());
    let tok = issuer.token("fleet-git/yah", &["git:read", "git:write", "git:write-qed", "git:write-relays", "git:write-heads"]);
    let park_tok = issuer.token_for_ref(
        "fleet-git/yah",
        &["git:read", "git:write", "git:write-camp-host"],
        Some("refs/camp-host/c1/"),
    );
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let a = start(tmp.path(), "a", &store, &issuer).await;
    let url = format!("{}/yah.git", a.url);
    ok(git(&work, &home, None, &["init", "-q", "-b", "main"]));
    (Rig { _tmp: tmp, home, work, store, a, url, tok, park_tok }, issuer)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cold_start_from_snapshot_and_journal_tail() {
    let (r, issuer) = rig_with_issuer().await;
    assert!(r.commit_push("c1", "main").await.1);
    assert!(r.commit_push("c2", "main").await.1);
    let snap = fleet_git::snapshot::take(&r.a.log, &r.a.locks, "yah", &r.repo_dir()).await.unwrap().unwrap();
    assert_eq!(snap.seq, 2);
    assert!(r.commit_push("c3", "main").await.1);
    assert!(r.commit_push("", "HEAD:refs/qed/run/x").await.1);

    // An empty volume elsewhere: restored from snapshot 2 plus entries 3..4.
    let tmp = tempfile::tempdir().unwrap();
    let b = start(tmp.path(), "b", &r.store, &issuer).await;
    let rep = &b.reports[0];
    assert_eq!((rep.mode, rep.base, rep.replayed.clone(), rep.seq), (Mode::Cold, 2, vec![3, 4], 4));
    let dir = b.root.join("yah.git");
    assert_eq!(disk_refs(&dir).await, journal_refs(&b.log.target, "yah").await);
    assert_eq!(fleet_git::stream::read_marker(&dir).unwrap().unwrap().seq, 4);
    hydrate::fsck(&fleet_git::gitbin::probe().unwrap().git, &dir).await.unwrap();
}

/// R997-B18: a journal entry naming a refname git refuses is skipped on
/// replay, so a journal written before the pre-receive check still hydrates.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cold_replay_skips_an_entry_with_an_invalid_refname() {
    let (r, issuer) = rig_with_issuer().await;
    let (tip, _) = r.commit_push("c1", "main").await;
    let t = &r.a.log.target;
    let mut bad = journal::entries_after(t, "yah", 0).await.unwrap().remove(0);
    bad.seq = 2;
    bad.pack = None;
    bad.pack_bytes = 0;
    bad.updates = vec![fleet_git::journal::JournalUpdate {
        refname: "refs/relays/R1/x.lock".into(),
        old: "0".repeat(40),
        new: tip.clone(),
    }];
    journal::append(t, &bad).await.unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let b = start(tmp.path(), "b", &r.store, &issuer).await;
    let rep = &b.reports[0];
    assert_eq!((rep.mode, rep.replayed.clone(), rep.seq), (Mode::Cold, vec![1, 2], 2));
    let refs = disk_refs(&b.root.join("yah.git")).await;
    assert_eq!(refs, vec![(tip, "refs/heads/main".to_string())]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warm_start_with_a_lagging_marker_replays_only_the_tail() {
    let (mut r, issuer) = rig_with_issuer().await;
    assert!(r.commit_push("c1", "main").await.1);
    // Keep a copy of the volume as of seq 1, then move on to seq 3.
    let saved = r.a.root.parent().unwrap().join("saved.git");
    let cp = Command::new("cp").args(["-R"]).arg(r.repo_dir()).arg(&saved).status().unwrap();
    assert!(cp.success());
    assert!(r.commit_push("c2", "main").await.1);
    let (tip, _) = r.commit_push("c3", "main").await;
    // Put the seq-1 volume back, then restart.
    r.stop().await;
    std::fs::remove_dir_all(r.repo_dir()).unwrap();
    std::fs::rename(&saved, r.repo_dir()).unwrap();
    r.restart(&issuer).await;
    let rep = &r.a.reports[0];
    assert_eq!((rep.mode, rep.base, rep.replayed.clone(), rep.seq), (Mode::Warm, 1, vec![2, 3], 3));
    assert!(r.remote("refs/heads/main").await.starts_with(&tip));
    assert_eq!(disk_refs(&r.repo_dir()).await, journal_refs(&r.a.log.target, "yah").await);
    // And the restarted writer appends seq 4 on top.
    assert!(r.commit_push("c4", "main").await.1);
    assert_eq!(journal::head(&r.a.log.target, "yah").await.unwrap(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_between_journal_create_and_ref_update_then_restart() {
    let (mut r, issuer) = rig_with_issuer().await;
    let (one, _) = r.commit_push("one", "main").await;
    r.a.log.inject(FailPoint::AfterJournalCreate);
    let (two, pushed) = r.commit_push("two", "main").await;
    assert!(!pushed);
    assert!(r.remote("refs/heads/main").await.starts_with(&one));
    r.restart(&issuer).await;
    let rep = &r.a.reports[0];
    assert_eq!((rep.mode, rep.replayed.clone(), rep.seq), (Mode::Warm, vec![2], 2));
    assert_eq!(disk_refs(&r.repo_dir()).await, journal_refs(&r.a.log.target, "yah").await);
    assert!(r.remote("refs/heads/main").await.starts_with(&two));
    assert!(unapplied(&r.a.log.target, "yah", &r.repo_dir()).await.unwrap().is_empty());
    // The writer continues at seq 3 rather than losing the fork fence.
    assert!(r.commit_push("three", "main").await.1);
    assert_eq!(journal::head(&r.a.log.target, "yah").await.unwrap(), 3);
}
