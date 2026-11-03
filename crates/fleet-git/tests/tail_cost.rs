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
        let exp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 300;
        let payload = serde_json::json!({
            "iss": "yah-camp", "aud": aud, "sub": "user:tester", "iat": 0, "exp": exp,
            "jti": "t", "scope": scopes,
        });
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


use fleet_git::journal;

struct Rig {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    work: PathBuf,
    store: Arc<dyn ObjectStore>,
    a: Instance,
    url: String,
    tok: String,
}

/// R978-S13 spike: cold rehydrate of an N-small-entry journal tail
/// (no snapshot). `cargo test -p fleet-git --test tail_cost -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn cold_rehydrate_of_a_small_entry_tail() {
    let n: usize = std::env::var("TAIL_N").ok().and_then(|v| v.parse().ok()).unwrap_or(500);
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let issuer = Issuer(AsymmetricKeyPair::<V4>::generate().unwrap());
    let tok = issuer.token("fleet-git/yah", &["git:read", "git:write", "git:write-qed", "git:write-relays", "git:write-heads"]);
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let a = start(tmp.path(), "a", &store, &issuer).await;
    let url = format!("{}/yah.git", a.url);
    ok(git(&work, &home, None, &["init", "-q", "-b", "main"]));
    let rig = Rig { _tmp: tempfile::tempdir().unwrap(), home, work, store: Arc::clone(&store), a, url, tok };
    let t0 = std::time::Instant::now();
    for i in 0..n {
        let (w, h, t, u) = (rig.work.clone(), rig.home.clone(), rig.tok.clone(), rig.url.clone());
        let m = format!("c{i}");
        tokio::task::spawn_blocking(move || {
            commit(&w, &h, &m);
            assert!(git(&w, &h, Some(&t), &["push", "-q", &u, "main"]).status.success());
        })
        .await
        .unwrap();
    }
    let build = t0.elapsed();
    let head = journal::head(&rig.a.log.target, "yah").await.unwrap();
    let mut bytes = 0u64;
    for s in 1..=head {
        bytes += journal::read(&rig.a.log.target, "yah", s).await.unwrap().unwrap().pack_bytes;
    }
    let git_v = String::from_utf8_lossy(&Command::new("git").arg("--version").output().unwrap().stdout).trim().to_string();
    // Cold: three fresh empty volumes.
    let mut times = Vec::new();
    for k in 0..3 {
        let d = tempfile::tempdir().unwrap();
        let b = start(d.path(), &format!("b{k}"), &store, &issuer).await;
        let r = &b.reports[0];
        assert_eq!((r.mode, r.replayed.len() as u64), (Mode::Cold, head));
        times.push(r.elapsed);
        b.task.abort();
    }
    println!("TAILCOST git={git_v} entries={head} pack_bytes_total={bytes} build_s={:.1}", build.as_secs_f64());
    for t in &times {
        println!("TAILCOST cold_rehydrate_s={:.3} per_entry_ms={:.2}", t.as_secs_f64(), t.as_secs_f64() * 1000.0 / head as f64);
    }
    rig.a.task.abort();
}
