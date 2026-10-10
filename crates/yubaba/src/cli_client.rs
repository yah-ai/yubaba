//! The HTTP client behind yubaba's own client verbs (`yubaba raft ...`),
//! and how each request is credentialed (R876-T22).
//!
//! Lives in the library rather than `main.rs` so a test can drive the exact
//! calls the CLI makes against an enforcing node.
//!
//! Credential order, resolved once per invocation, applied per request:
//! 1. an operator key file (`--operator-key-file` / `YAH_OPERATOR_KEY_FILE`)
//!    that exists → a fresh operator token per request;
//! 2. else `YUBABA_BEARER_TOKEN` → sent as-is. This is a PER-INVOCATION
//!    token the caller minted seconds earlier (e.g. a laptop minting for an
//!    ssh'd `yubaba raft add-learner`), passed through the environment so it
//!    never lands in argv. It is never written to disk and never a stored
//!    credential; the node's 24h ceiling still bounds it;
//! 3. else a cluster key file (`--cluster-key-file` /
//!    `YUBABA_CLUSTER_KEY_FILE`) → a fresh peer token, on PEER routes only
//!    (a peer token on an operator route is a 403 in both modes);
//! 4. else unsigned.

use std::path::Path;

use anyhow::{anyhow, bail, Result};
use yubaba_auth_token::{OperatorSigner, PeerSigner};

/// Env carrying a caller-minted, per-invocation bearer token. See the
/// module doc: never a stored credential.
pub const BEARER_TOKEN_ENV: &str = "YUBABA_BEARER_TOKEN";

/// Which credential tier a route needs; mirrors `build_router`'s sub-routers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    Peer,
    Operator,
}

/// How a client verb credentials its requests.
#[derive(Clone, Debug, Default)]
pub struct CliAuth {
    operator: OperatorSigner,
    bearer: Option<String>,
    peer: PeerSigner,
}

impl CliAuth {
    /// Resolve the credential in the module-doc order. `bearer` is the
    /// value of [`BEARER_TOKEN_ENV`], passed in so tests need no process env.
    pub fn resolve(
        operator_key_file: Option<&Path>,
        bearer: Option<String>,
        cluster_key_file: Option<&Path>,
    ) -> Result<Self> {
        let operator = match operator_key_file {
            Some(p) => yubaba_auth_token::operator_signer_for_optional_file(p).map_err(|e| anyhow!(e))?,
            None => OperatorSigner::unsigned(),
        };
        let bearer = bearer.map(|b| b.trim().to_string()).filter(|b| !b.is_empty());
        let peer = PeerSigner::from_key_file(cluster_key_file, "svc:yubaba-cli".into())
            .map_err(|e| anyhow!(e))?;
        Ok(Self { operator, bearer, peer })
    }

    /// Attach this invocation's credential for a route of `class`.
    pub fn sign(&self, rb: reqwest::RequestBuilder, class: RouteClass) -> reqwest::RequestBuilder {
        if self.operator.is_signing() {
            return self.operator.sign(rb);
        }
        if let Some(b) = &self.bearer {
            return rb.bearer_auth(b);
        }
        match class {
            RouteClass::Peer => self.peer.sign(rb),
            RouteClass::Operator => rb,
        }
    }
}

/// `GET {daemon}/raft/status` (Peer) as JSON.
pub async fn raft_status(
    http: &reqwest::Client,
    auth: &CliAuth,
    daemon: &str,
) -> Result<serde_json::Value> {
    let resp = auth
        .sign(http.get(format!("{daemon}/raft/status")), RouteClass::Peer)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("GET /raft/status failed ({status}): {body}");
    }
    Ok(resp.json().await?)
}

/// `POST {daemon}{path}` with a JSON body on an OPERATOR route (the raft
/// membership verbs). `Ok(body)` on 2xx; `Err` names `verb`, status, body.
pub async fn operator_post(
    http: &reqwest::Client,
    auth: &CliAuth,
    daemon: &str,
    path: &str,
    body: &serde_json::Value,
    verb: &str,
) -> Result<String> {
    let resp = auth
        .sign(http.post(format!("{daemon}{path}")), RouteClass::Operator)
        .json(body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if status.is_success() {
        Ok(text)
    } else {
        bail!("{verb} failed ({status}): {text}")
    }
}
