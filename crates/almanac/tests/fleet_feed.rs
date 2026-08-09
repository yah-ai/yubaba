//! R707-F4 — the authenticated feed, end to end through the real config path.
//!
//! What the unit tests in `r2.rs` cannot show: that a feed TOML declaring
//! `kind = "r2-private"` resolves its credentials off disk, makes a **signed**
//! request for the object, and lands the bytes in the artifact unchanged. Every
//! step here goes through the shipped surface — `FeedLoader::load` →
//! `FeedRunner::run` — rather than constructing the source by hand, because the
//! seam most likely to break is the config→adapter wiring, and a test that
//! bypasses it would keep passing while the shipped feed 403s.
//!
//! The stub stands in for R2 at the `endpoint` override. It asserts the one
//! property the whole variant exists for: the request carries an
//! `Authorization: AWS4-HMAC-SHA256 …` header. `cdn.yah.dev/yah/index.json`, the
//! releases feed's object, is fetched with no such header **by design** — the
//! `releases_feed_*` test at the bottom pins that the two paths did not converge.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{extract::State, http::HeaderMap, routing::get, Router};
use yah_almanac::{FeedLoader, FeedRunner, OnChangeConfig, SourceConfig};

/// The published projection, byte-for-byte the shape `xtask fleet-index` renders
/// and `yah_fleet_metrics::PublishedIndexInventory` parses.
const FLEET_INDEX: &str = r#"{
  "schema_version": 1,
  "source_commit": "6433bc76612da5faa88a41417a2f7ef009f28101",
  "generated_at": "2026-08-05T05:00:00Z",
  "machines": [
    { "name": "us-west-001", "region": "us-west" },
    { "name": "us-west-002", "region": "us-west" }
  ]
}"#;

#[derive(Clone, Default)]
struct Seen {
    authorization: Arc<Mutex<Option<String>>>,
}

async fn serve_index(State(seen): State<Seen>, headers: HeaderMap) -> String {
    *seen.authorization.lock().unwrap() = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    FLEET_INDEX.to_string()
}

/// A stub R2 at `{endpoint}/{bucket}/{key}` — the path-style addressing
/// `R2ObjectStore` uses, which is why one route is enough.
async fn spawn_stub_r2() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/yah-fleet/fleet/index.json", get(serve_index))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://127.0.0.1:{port}"), seen)
}

/// A workspace holding `.yah/almanac/fleet.toml` plus the two credential files
/// the deploy layer would have mounted, shaped exactly like the shipped feed.
fn workspace_with_fleet_feed(root: &std::path::Path, endpoint: &str) {
    let almanac = root.join(".yah/almanac");
    std::fs::create_dir_all(&almanac).unwrap();
    let secrets = root.join("run/secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    // Newline-terminated on purpose: that is what `echo` and most secret rails
    // produce, and an untrimmed key reaches the edge as an unexplained
    // signature mismatch.
    std::fs::write(secrets.join("fleet-r2-access-key-id"), "TESTACCESSKEYID\n").unwrap();
    std::fs::write(secrets.join("fleet-r2-secret-key"), "testsecretkey\n").unwrap();

    std::fs::write(
        almanac.join("fleet.toml"),
        format!(
            r#"
[feed]
name = "fleet"

[feed.source]
kind = "r2-private"
account_id = "acct-under-test"
bucket = "yah-fleet"
key = "fleet/index.json"
id = "fleet"
endpoint = "{endpoint}"
access_key_id = {{ file = "{access}" }}
secret_access_key = {{ file = "{secret}" }}

[feed.trigger]
kind = "webhook"

[feed.emit]
artifact = ".yah/infra/state/fleet-index.json"

[feed.emit.on_change]
kind = "reload"
service = "yah-cloud-admin"
"#,
            access = secrets.join("fleet-r2-access-key-id").display(),
            secret = secrets.join("fleet-r2-secret-key").display(),
        ),
    )
    .unwrap();
}

/// The relay's third verify criterion, from the consumer side: the index is
/// reachable only with the credential. The request is signed, the bytes land
/// verbatim, and the run reports the `reload` binding.
#[tokio::test]
async fn a_fleet_change_lands_in_the_artifact_over_a_signed_request() {
    let (endpoint, seen) = spawn_stub_r2().await;
    let tmp = tempfile::tempdir().unwrap();
    workspace_with_fleet_feed(tmp.path(), &endpoint);

    let cfg = FeedLoader::new(tmp.path().join(".yah/almanac"))
        .load("fleet")
        .expect("the shipped feed shape must load");
    assert!(matches!(cfg.feed.source, SourceConfig::R2Private { .. }));

    let result = FeedRunner::new(cfg, tmp.path())
        .run()
        .await
        .expect("the authenticated fetch must succeed against the stub");

    // 1. The request was SIGNED. This is the whole asymmetry with the releases
    //    feed; an anonymous GET here would mean the index is only as private as
    //    its URL.
    let auth = seen.authorization.lock().unwrap().clone();
    let auth = auth.expect("the fetch sent no Authorization header at all");
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 "),
        "expected a SigV4 credential, got: {auth}"
    );
    assert!(
        auth.contains("Credential=TESTACCESSKEYID/"),
        "the key came from the mounted file, newline trimmed: {auth}"
    );

    // 2. The bytes landed VERBATIM — no ReleaseFeed envelope, nothing added.
    //    `PublishedIndexInventory` parses this file directly and would reject a
    //    wrapper.
    let artifact = tmp.path().join(".yah/infra/state/fleet-index.json");
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifact).unwrap()).unwrap();
    assert_eq!(
        written,
        serde_json::from_str::<serde_json::Value>(FLEET_INDEX).unwrap()
    );
    assert!(
        written.get("releases").is_none() && written.get("fetched_at").is_none(),
        "almanac must not wrap a payload whose schema it does not own"
    );

    // 3. The change fired, and it carries the mirror binding rather than a route.
    match result.on_change {
        Some(OnChangeConfig::Reload { ref service }) => assert_eq!(service, "yah-cloud-admin"),
        ref other => panic!("expected a reload on_change, got {other:?}"),
    }
}

/// Change suppression holds on this path too: a re-poke that finds the same
/// index must not tell every consumer to re-read. Same guarantee the release
/// feed gets, reached through a different comparison.
#[tokio::test]
async fn a_second_run_over_an_unchanged_index_suppresses_the_reload() {
    let (endpoint, _seen) = spawn_stub_r2().await;
    let tmp = tempfile::tempdir().unwrap();
    workspace_with_fleet_feed(tmp.path(), &endpoint);
    let load = || {
        FeedLoader::new(tmp.path().join(".yah/almanac"))
            .load("fleet")
            .unwrap()
    };

    let first = FeedRunner::new(load(), tmp.path()).run().await.unwrap();
    assert!(first.on_change.is_some(), "the first run is always a change");

    let second = FeedRunner::new(load(), tmp.path()).run().await.unwrap();
    assert!(
        second.on_change.is_none(),
        "an unchanged index must not fire a reload"
    );
}

/// A credential the deploy layer failed to deliver must be reported as *that* —
/// naming the path it looked at — rather than surfacing three layers down as a
/// `403` from the edge, which reads as a scope problem and sends you to the
/// Cloudflare dashboard.
#[tokio::test]
async fn a_missing_credential_names_the_reference_and_never_reaches_the_network() {
    let (endpoint, seen) = spawn_stub_r2().await;
    let tmp = tempfile::tempdir().unwrap();
    workspace_with_fleet_feed(tmp.path(), &endpoint);
    std::fs::remove_file(tmp.path().join("run/secrets/fleet-r2-secret-key")).unwrap();

    let cfg = FeedLoader::new(tmp.path().join(".yah/almanac"))
        .load("fleet")
        .unwrap();
    let err = FeedRunner::new(cfg, tmp.path()).run().await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("secret_access_key"), "names the component: {msg}");
    assert!(msg.contains("fleet-r2-secret-key"), "names the file: {msg}");
    assert!(
        seen.authorization.lock().unwrap().is_none(),
        "nothing should have been sent — the failure is local"
    );
    assert!(
        !tmp.path().join(".yah/infra/state/fleet-index.json").exists(),
        "a failed fetch must not leave an artifact behind for a consumer to trust"
    );
}

/// Guards the REAL `.yah/almanac/fleet.toml`, not a copy of it — the same
/// reason `config.rs`'s `the_shipped_releases_feed_parses` guards the real
/// releases feed. A `kind` rename here that forgot the shipped file would leave
/// the fleet feed silently unloadable, and the symptom is a monitor that is
/// running, healthy, and describing a fleet it never fetched.
///
/// The three properties pinned are the three that are load-bearing rather than
/// stylistic: the source is the authenticated one, the credentials are
/// references rather than values, and the `on_change` names the service the
/// receiver will compare itself against.
#[test]
fn the_shipped_fleet_feed_parses_and_keeps_its_credentials_out_of_git() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("almanac lives at <root>/oss/yubaba/crates/almanac");
    let almanac_dir = repo_root.join(".yah/almanac");
    if !almanac_dir.join("fleet.toml").exists() {
        return; // exported standalone — nothing to guard
    }
    let cfg = FeedLoader::new(&almanac_dir)
        .load("fleet")
        .expect("the shipped fleet feed must load");

    match cfg.feed.source {
        SourceConfig::R2Private {
            ref bucket,
            ref access_key_id,
            ref secret_access_key,
            ..
        } => {
            assert_ne!(
                bucket, "yah-dev",
                "yah-dev is public at cdn.yah.dev; this index names mesh IPs and hostkey \
                 fingerprints and must live in a bucket with no public custom domain"
            );
            // The enum has no inline variant, so this cannot fail today — it is
            // here so that adding one is a deliberate act with a red test
            // attached, rather than a convenience someone reaches for.
            for (which, cred) in [
                ("access_key_id", access_key_id),
                ("secret_access_key", secret_access_key),
            ] {
                assert!(
                    matches!(cred, yah_almanac::CredentialRef::File(_)),
                    "{which} must be a file reference — this file is git-tracked, and a \
                     credential written into it would publish what the credential protects"
                );
            }
        }
        ref other => panic!(
            "the fleet feed must source the AUTHENTICATED index — an anonymous source would \
             mean the fleet map is only as private as its URL. Got {other:?}"
        ),
    }

    match cfg.feed.emit.on_change {
        Some(OnChangeConfig::Reload { ref service }) => assert_eq!(service, "yah-cloud-admin"),
        // Not a style preference: a feed with no on_change is rejected by the
        // receiver with 422 before it runs, and a mesofact-rebuild would send
        // the poke to a renderer that has no such route.
        ref other => panic!("the fleet feed must carry a `reload` binding, got {other:?}"),
    }
}

/// The by-design-public path must not have been dragged along. `r2-index` is
/// the releases feed's source and it is anonymous on purpose ("materialize is
/// unauthenticated by design"); if a future edit gave every source a credential
/// requirement, `/releases` would break the first time one expired — on the one
/// path that has users on it.
#[test]
fn the_releases_feed_still_declares_an_unauthenticated_source() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .expect("almanac lives at <root>/oss/yubaba/crates/almanac");
    let almanac_dir = repo_root.join(".yah/almanac");
    if !almanac_dir.join("releases.toml").exists() {
        return; // exported standalone — nothing to guard
    }
    let cfg = FeedLoader::new(&almanac_dir).load("releases").unwrap();
    assert!(
        matches!(cfg.feed.source, SourceConfig::R2Index { .. }),
        "releases must stay on the anonymous r2-index source — the node tier \
         deliberately holds no read credential, and R707-F4 inverted that for \
         the fleet feed ONLY"
    );
}
