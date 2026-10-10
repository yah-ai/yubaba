//! R876-T18 step 1 — a cluster where EVERY node enforces `--auth-mode
//! require` still elects, replicates and forwards, because every node signs
//! its own peer traffic with the shared cluster key.
//!
//! This is the property the roll's step 3 (flip to require) bets the fleet's
//! quorum on. Before step 1 an enforcing node 401'd every `/raft/vote` and
//! `/raft/append-entries` it received, which takes it out of the quorum while
//! systemd still reports it active — so a leader agreed on here is the
//! assertion, not a precondition.

use std::time::Duration;

use reqwest::StatusCode;
use yubaba::cluster_policy::ClusterPolicy;
use yubaba_auth_token::{cluster_key_from_hex, generate_cluster_key_hex, mint_peer_token};
use yubaba::raft::{self, YubabaRequest};
use yubaba::runtime::DummyRuntime;
use yubaba_test_harness::test_cluster_enforcing;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn an_all_require_cluster_elects_replicates_and_forwards_signed() {
    let key = generate_cluster_key_hex().expect("cluster key");
    let cluster = test_cluster_enforcing(DummyRuntime, 3, ClusterPolicy::fleet(), &key)
        .await
        .expect("enforcing cluster");

    // Votes and heartbeats are the raft transport's own RPCs: an unsigned
    // transport never gets past this line.
    let leader = cluster
        .wait_for_agreed_leader(Duration::from_secs(30))
        .await
        .expect("an all-require cluster must still elect");
    let follower = (0..cluster.node_count()).find(|i| *i != leader).unwrap();

    // A follower's write goes out over `/raft/write` on the leader — a Peer
    // route — through the node's own `ServerState::http`.
    let state = cluster.server_state(follower).expect("follower state");
    let follower_raft = cluster.raft(follower).expect("follower raft");
    raft::client_write_forwarded(
        follower_raft,
        &state.http,
        YubabaRequest::AcquireLock {
            key: "r876-t18".into(),
            owner: "raft_peer_auth".into(),
            ttl_secs: 60,
            acquired_at: now() as u64,
        },
    )
    .await
    .expect("a follower's forwarded write must reach the enforcing leader");

    // Non-vacuity: the nodes really are enforcing. Anonymous is refused, a
    // peer token minted under the same key is served.
    let base = &cluster.yubaba(follower).base_url;
    let http = reqwest::Client::new();
    let anon = http.get(format!("{base}/raft/status")).send().await.unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED, "nodes must be in require mode");

    let sym = cluster_key_from_hex(&key).unwrap();
    let token = mint_peer_token(&sym, "node:test", 300, now()).unwrap();
    let signed = http
        .get(format!("{base}/raft/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(signed.status(), StatusCode::OK);

    // The floater replication routes are Peer class (node-to-node, including
    // the owner's unattended re-publish), so a peer token opens them...
    let floaters = http
        .get(format!("{base}/workloads/floaters"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(floaters.status(), StatusCode::OK, "floater replication is Peer class");

    // ...while the deploy that STARTS a floater stays Operator: a peer token
    // is a present-but-insufficient credential, refused in both modes.
    let deploy = http
        .post(format!("{base}/workloads/deploy"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "spec": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(deploy.status(), StatusCode::FORBIDDEN, "deploy stays Operator class");
}

/// R876-T18 step 1, out-of-process half: the tenant streamer cannot link
/// yubaba (W253 tenet 1), so it mints through `yubaba-auth-token` from a key
/// FILE. Against an enforcing node, its signed `HttpOwnership` reads
/// `/tenants/{id}` and the identical unsigned client is refused — which is
/// exactly the outage step 3 would cause if the streamer had been skipped.
#[tokio::test]
async fn the_tenant_streamer_reads_ownership_from_an_enforcing_node_only_when_keyed() {
    use workload_spec::TenantId;
    use yubaba_auth_token::PeerSigner;
    use yubaba_tenant_streamer::{HttpOwnership, OwnershipSource};

    let key = generate_cluster_key_hex().expect("cluster key");
    let cluster = test_cluster_enforcing(DummyRuntime, 3, ClusterPolicy::fleet(), &key)
        .await
        .expect("enforcing cluster");
    let leader = cluster
        .wait_for_agreed_leader(Duration::from_secs(30))
        .await
        .expect("an all-require cluster must still elect");
    let base = cluster.yubaba(leader).base_url.clone();

    let dir = tempfile::TempDir::new().unwrap();
    let key_file = dir.path().join("cluster.key");
    std::fs::write(&key_file, format!("{key}\n")).unwrap();
    let signer = PeerSigner::from_key_file(Some(&key_file), "svc:tenant-streamer@node:1".into())
        .expect("a readable key file");

    let tenant = TenantId("r876-t18".into());
    // No record for this tenant: a served read answers 404, which the client
    // reports as "nobody owns it" — a successful read, not an error.
    let keyed = HttpOwnership::new(base.clone(), 1, signer);
    let seen = keyed
        .ownership(&tenant)
        .await
        .expect("a keyed streamer must be served by an enforcing node");
    assert_eq!(seen.fencing_token, None);

    let unkeyed = HttpOwnership::new(base, 1, PeerSigner::unsigned());
    let err = unkeyed
        .ownership(&tenant)
        .await
        .expect_err("an unkeyed streamer must be refused by an enforcing node");
    assert!(format!("{err:#}").contains("401"), "expected a 401, got: {err:#}");
}

/// R876-T22: the `yubaba raft` client verbs against an all-require cluster.
/// An Operator membership verb (`transfer-leader`) 401s with no credential,
/// and succeeds with an operator key file and with a caller-minted
/// `YUBABA_BEARER_TOKEN`. The same `cli_client` calls the CLI makes.
#[tokio::test]
async fn yubaba_raft_cli_verbs_sign_with_an_operator_key_file_or_a_bearer() {
    use yubaba::cli_client::{self, CliAuth};

    let key = generate_cluster_key_hex().expect("cluster key");
    let cluster = test_cluster_enforcing(DummyRuntime, 3, ClusterPolicy::fleet(), &key)
        .await
        .expect("enforcing cluster");
    let (_public, secret) = yubaba_test_harness::enforcing_operator_keypair_hex();
    let http = reqwest::Client::new();

    let transfer = |auth: CliAuth, leader: usize| {
        let base = cluster.yubaba(leader).base_url.clone();
        let to = ((leader + 1) % cluster.node_count()) as u64 + 1;
        let http = http.clone();
        async move {
            let body = serde_json::json!({ "to": to });
            cli_client::operator_post(&http, &auth, &base, "/raft/transfer-leader", &body, "transfer-leader").await
        }
    };

    // Neither credential: refused outright.
    let leader = cluster.wait_for_agreed_leader(Duration::from_secs(30)).await.unwrap();
    let err = transfer(CliAuth::resolve(None, None, None).unwrap(), leader)
        .await
        .expect_err("a tokenless membership verb must be refused");
    assert!(format!("{err:#}").contains("401"), "expected a 401, got: {err:#}");

    // A cluster key is not enough for an Operator route: the peer signer is
    // only applied to Peer routes, so this is still tokenless -> 401.
    let tmp = tempfile::TempDir::new().unwrap();
    let ck = tmp.path().join("cluster.key");
    std::fs::write(&ck, &key).unwrap();
    let err = transfer(CliAuth::resolve(None, None, Some(&ck)).unwrap(), leader)
        .await
        .expect_err("a cluster key must not open an Operator verb");
    assert!(format!("{err:#}").contains("401"), "expected a 401, got: {err:#}");

    // Operator key file: a fresh operator token per request.
    let ok = tmp.path().join("operator.key");
    std::fs::write(&ok, secret).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::env::set_var("YAH_OPERATOR_SUBJECT", "user:raft-cli-test");
    transfer(CliAuth::resolve(Some(&ok), None, None).unwrap(), leader)
        .await
        .expect("an operator key file must open transfer-leader");

    // Caller-minted bearer, as an ssh'd invocation receives it.
    let leader = cluster.wait_for_agreed_leader(Duration::from_secs(30)).await.unwrap();
    let sk = yubaba_auth_token::operator_secret_from_hex(secret).unwrap();
    let token = yubaba_auth_token::mint_operator_token(&sk, "user:raft-cli-test", 300, now()).unwrap();
    transfer(CliAuth::resolve(None, Some(token), None).unwrap(), leader)
        .await
        .expect("a YUBABA_BEARER_TOKEN must open transfer-leader");

    // Peer route through the same client: the cluster key alone serves status.
    cli_client::raft_status(&http, &CliAuth::resolve(None, None, Some(&ck)).unwrap(), &cluster.yubaba(leader).base_url)
        .await
        .expect("a cluster key must open GET /raft/status");
}
