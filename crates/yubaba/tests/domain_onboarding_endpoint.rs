//! `GET /domains/{domain}/onboarding` — the read the tenant-facing onboarding
//! page renders from (R852-F2 / W267 §Decision 2).
//!
//! Every test here is about the endpoint refusing to state something it was not
//! given, because the consumer of this payload is a human typing DNS records
//! into a registrar we do not control. A wrong answer here does not fail loudly
//! — it fails as "the CA says there is no TXT record", with both ends looking
//! correct in isolation.
//!
//! Nothing here touches the environment. The delegate zone and the public
//! ingress address are resolved once at boot into `ServerState` (main.rs) and
//! the handler reads them from there, so these tests build a node with a known
//! configuration instead of racing `set_var` against the other modules of this
//! group binary — which run in parallel with them (see `tests/main.rs`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;
use yah_object_store::InMemoryObjectStore;
use yubaba::cert_store::{Enrollment, ObjectCertStore};

const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// A router whose cert store has `enrolled` registered (and nothing else),
/// configured with `zone` as its delegate zone and `ingress` as its public
/// address list.
fn app_with(
    enrolled: &[&str],
    zone: Option<&str>,
    ingress: &[&str],
) -> (TempDir, axum::Router) {
    let dir = TempDir::new().unwrap();
    let mem = Arc::new(InMemoryObjectStore::new());
    let certs = ObjectCertStore::new(mem, LE);
    for domain in enrolled {
        certs
            .enroll(
                domain,
                &Enrollment::new(
                    // The internal backend — the single most available WRONG
                    // answer for a tenant's A record, which is why every test
                    // below checks it does not appear in the response.
                    "127.0.0.1:8443".parse::<SocketAddr>().unwrap(),
                    SystemTime::UNIX_EPOCH,
                ),
            )
            .expect("enroll");
    }
    let state = Arc::new(
        yubaba::ServerState::load(dir.path().join("identity.json"))
            .unwrap()
            .with_cert_store(certs)
            .with_domain_onboarding(
                zone.map(str::to_string),
                ingress.iter().map(|s| s.to_string()).collect(),
            ),
    );
    (dir, yubaba::build_router(state))
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// The enrollment set is the structural allowlist (R779 P5). Rendering
/// onboarding for a name outside it would walk a tenant through creating
/// records that can never validate — and would let anyone mint plausible
/// instructions for a domain this deployment will not serve.
#[tokio::test]
async fn a_domain_that_was_never_enrolled_is_404_not_a_rendered_instruction() {
    let (_dir, app) = app_with(&["shop.tenant.io"], Some("acme.yah.dev"), &["203.0.113.7"]);
    let (status, body) = get(app, "/domains/other.tenant.io/onboarding").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let err = body["error"].as_str().unwrap_or_default();
    assert!(err.contains("not enrolled"), "{body}");
    assert!(err.contains("yubaba domain enroll"), "{body}");
    // And it named nothing a tenant could act on.
    assert!(body.get("challenge_record").is_none(), "{body}");
}

/// No cert store means the enrollment set cannot be read at all. That is a node
/// misconfiguration, not "this domain is unknown" — answering 404 would send
/// the operator hunting for a missing enrollment that is actually there.
#[tokio::test]
async fn no_cert_store_is_503_naming_the_variable_not_404() {
    let dir = TempDir::new().unwrap();
    let state = Arc::new(yubaba::ServerState::load(dir.path().join("identity.json")).unwrap());
    let (status, body) = get(yubaba::build_router(state), "/domains/a.io/onboarding").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("YUBABA_CERT_STORE_BUCKET"),
        "{body}"
    );
}

/// An unconfigured node: no delegate zone, no public ingress.
///
/// Neither absence is an error, and neither is a licence to guess.
#[tokio::test]
async fn an_unconfigured_node_admits_what_it_does_not_know_rather_than_guessing() {
    let (_dir, app) = app_with(&["shop.tenant.io"], None, &[]);
    let (status, body) = get(app, "/domains/shop.tenant.io/onboarding").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["domain"], "shop.tenant.io");
    assert_eq!(body["address_record"]["targets"], serde_json::json!([]));
    assert!(
        !body.to_string().contains("127.0.0.1"),
        "the enrollment's INTERNAL backend must never surface as a tenant A record: {body}"
    );
    // Undelegated renders as the misconfiguration it is, naming the variable.
    assert_eq!(body["challenge_record"]["delegated"], serde_json::json!(false));
    assert_eq!(body["challenge_record"]["type"], serde_json::json!("TXT"));
    assert!(
        body["challenge_record"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains("YUBABA_DOMAIN_ISSUER_DELEGATE_ZONE"),
        "{body}"
    );
}

/// A configured node: both records, both derived by the issuer's own function.
#[tokio::test]
async fn a_configured_node_reports_both_records_verbatim() {
    let (_dir, app) = app_with(
        &["shop.tenant.io"],
        Some("acme.yah.dev"),
        &["203.0.113.7", "2001:db8::7"],
    );
    let (status, body) = get(app, "/domains/shop.tenant.io/onboarding").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["address_record"]["targets"],
        serde_json::json!(["203.0.113.7", "2001:db8::7"]),
        "a comma- or space-separated list becomes one record per target, because \
         a joined string is not a valid record on its own"
    );
    assert_eq!(body["challenge_record"]["delegated"], serde_json::json!(true));
    assert_eq!(body["challenge_record"]["type"], serde_json::json!("CNAME"));
    // The target is the issuer's own derivation, not a local format!().
    assert_eq!(
        body["challenge_record"]["target"],
        serde_json::json!("shop.tenant.io.acme.yah.dev")
    );
    assert_eq!(
        body["challenge_record"]["name"],
        serde_json::json!("_acme-challenge.shop.tenant.io")
    );
    assert!(
        !body.to_string().contains("127.0.0.1"),
        "the enrollment's INTERNAL backend must never surface as a tenant record: {body}"
    );
}

/// The env parse the boot path uses. Separators are `,`/space/tab/newline
/// because an operator writing a systemd `Environment=` line will reach for
/// either, and an address list that silently becomes one bogus entry is a
/// record a tenant cannot create.
#[test]
fn public_ingress_targets_splits_on_the_separators_an_operator_would_type() {
    use yubaba::public_ingress_targets as parse;
    assert_eq!(parse(None), Vec::<String>::new());
    assert_eq!(parse(Some("  ".into())), Vec::<String>::new());
    assert_eq!(parse(Some(",, ,".into())), Vec::<String>::new());
    assert_eq!(parse(Some("203.0.113.7".into())), vec!["203.0.113.7"]);
    assert_eq!(
        parse(Some(" 203.0.113.7 , 2001:db8::7 ".into())),
        vec!["203.0.113.7", "2001:db8::7"]
    );
    assert_eq!(
        parse(Some("203.0.113.7 2001:db8::7".into())),
        vec!["203.0.113.7", "2001:db8::7"]
    );
}
