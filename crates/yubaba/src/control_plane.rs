//! @arch:layer(core)
//! @arch:role(net)
//!
//! The **yah control plane** listener — A032 §"yah-aware control plane" /
//! A043 §"yah-aware control plane via iroh" / W242 §"four planes".
//!
//! Yubaba binds an [`mshr::Endpoint`] whose `NodeId` *is* this machine's
//! hostkey (see [`crate::identity`]), so any yah-aware caller — a camp
//! daemon, the desktop, the mobile app, another agent — can dial the node
//! by `NodeId` over NAT-punched QUIC instead of by IP/SSH. That NodeId is
//! already published on `GET /identity` (`node_id`, R593-T2); this module
//! is the half that actually *listens* on it.
//!
//! Part of R609-F1 — canonical annotation in
//! `.yah/docs/working/W242-yubaba-mesh-raft-roadmap.md`.
//!
//! ## What this layer deliberately is not
//!
//! - **Not the raft hop.** yubaba↔yubaba raft RPC stays on the WireGuard
//!   cluster mesh (A032: "tunneling that over iroh was considered and
//!   rejected"). Nothing here is reachable from the raft transport.
//! - **Not the source of discovery policy.** [`Planes::seeds`] carries an
//!   [`mshr::Seeds`] and this module applies it, but the defaults, the
//!   override spelling and the precedence rule all live in `mshr::seeds`
//!   (R609-F4) so yubaba and every yah-side dialer read one definition.
//!   [`mshr::Seeds::none`] reproduces the pre-F4 posture: no address-lookup
//!   lane and no relay map, so a dialer needs a fully-formed `EndpointAddr`.
//! - **Not the account layer.** mshr's QUIC/TLS handshake authenticates
//!   the peer's `NodeId` by construction; *whether that NodeId is
//!   entitled to reach this node* is answered by [`admission`] (R609-F3,
//!   an [`mshr::Acceptor`] over the cheers enrollment ledger plus a
//!   static allowlist). What the caller's **principal** may then *do* is
//!   a third question, and it belongs to the lane's own payload
//!   (kamaji/cheers scopes), not to the listener.
//!
//! The protocol on [`CONTROL_PLANE_ALPN`] is one request/response: the
//! dialer opens a bidirectional stream and finishes it; yubaba replies
//! with a JSON [`Hello`] and closes. That is enough to prove reachability
//! end-to-end (which a bound-but-unaccepted endpoint is not), and it is
//! the seam the real RPC surface attaches to — R609-F2 registers its own
//! ALPN on the same endpoint rather than reshaping this one.
//!
//! ## Lanes
//!
//! R609-F2 landed that second ALPN: [`crate::camp_rpc`], which serves a
//! workspace's `yah camp --stdio` JSON-RPC to a NodeId dial. Lanes are
//! opt-in per [`Planes`], and the ALPN list an endpoint advertises is
//! derived from the same value — an endpoint never negotiates an ALPN it
//! has no handler for, because "handshake succeeded then the connection
//! vanished" is a far worse diagnostic than a clean ALPN rejection.
//!
//! A lane that does more than greet also requires an
//! [`Admission`](admission::Admission) policy that actually gates
//! callers: admitting a camp-RPC dial spawns a process, so
//! [`Planes::camp_rpc_lane`] withholds that lane entirely under
//! `Admission::AllowAll` rather than serving it to any NodeId on the
//! internet. Same derivation rule — the ALPN list and the handler map
//! both read that one accessor, so a withheld lane is also an
//! unadvertised one.

pub mod admission;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub use admission::{Admission, Entitlement, DEFAULT_ENROLLMENT_TTL};

/// ALPN for the yah control plane, as a string (this is the spelling that
/// goes on the wire and onto `GET /identity`).
pub const CONTROL_PLANE_ALPN_STR: &str = "yah/control/1";

/// ALPN for the yah control plane. Versioned in the string so a future
/// incompatible framing is a second ALPN on the same endpoint rather than
/// a flag day.
pub const CONTROL_PLANE_ALPN: &[u8] = CONTROL_PLANE_ALPN_STR.as_bytes();

/// Cap on the request bytes read from a control-plane stream before the
/// [`Hello`] reply. The request half is currently empty; the cap exists so
/// an unauthenticated dialer cannot make yubaba buffer without bound.
const MAX_REQUEST_BYTES: usize = 4096;

/// The greeting yubaba writes back on [`CONTROL_PLANE_ALPN`].
///
/// Deliberately the same facts `GET /identity` reports, so a caller that
/// reached the node over iroh knows it is talking to the same machine the
/// HTTP surface describes — without needing the HTTP surface to be
/// reachable at all, which is the entire point of this plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Always `"yah-yubaba"`. Lets a dialer that guessed wrong about what
    /// is on the far end fail with a readable error.
    pub name: String,
    /// This daemon's crate version, matching `GET /health`'s `version`.
    pub version: String,
    /// Hex-encoded mshr `NodeId` — equal to `GET /identity`'s `node_id`
    /// and to the `NodeId` the dialer just authenticated in the handshake.
    pub node_id: String,
    /// OpenSSH-style hostkey fingerprint (`SHA256:…`), for operators and
    /// fleet tooling that key off the fingerprint rather than the NodeId.
    /// `None` on a node whose identity failed to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostkey_fingerprint: Option<String>,
}

impl Hello {
    /// Build the greeting for a node with the given identity facts.
    pub fn new(node_id: impl Into<String>, hostkey_fingerprint: Option<String>) -> Self {
        Self {
            name: "yah-yubaba".to_string(),
            version: crate::VERSION.to_string(),
            node_id: node_id.into(),
            hostkey_fingerprint,
        }
    }
}

/// Which lanes this node's control-plane endpoint serves, and who is
/// admitted to them.
///
/// The greeting on [`CONTROL_PLANE_ALPN`] is served to every *admitted*
/// caller — it is the reachability probe, and a node that answers
/// nothing is indistinguishable from a node that is down. Everything
/// else is opt-in, because every additional lane is additional surface.
#[derive(Debug, Clone, Default)]
pub struct Planes {
    /// Serve `yah camp --stdio` over [`crate::camp_rpc::CAMP_RPC_ALPN`].
    /// `None` leaves that ALPN unadvertised entirely — and so does an
    /// ungated [`Self::admission`]; see [`Self::camp_rpc_lane`].
    pub camp_rpc: Option<crate::camp_rpc::CampRpcConfig>,
    /// Who may open a connection at all (R609-F3). Defaults to
    /// [`Admission::AllowAll`], the pre-F3 posture: fine for the bare
    /// greeting, not enough to unlock a lane with side effects.
    pub admission: Admission,
    /// Discovery / relay configuration for the endpoint (R609-F4).
    ///
    /// This is what makes the node reachable *by NodeId alone*: without a
    /// relay map a peer behind a symmetric NAT can never punch to it, and
    /// without a resolver lane nobody can turn its NodeId into an address in
    /// the first place. `None` keeps [`mshr::Seeds::none`] — the pre-F4
    /// posture, where a dialer must already hold a full `EndpointAddr`.
    ///
    /// `Option` rather than a plain `Seeds` because the difference between
    /// "the operator configured nothing" and "the operator configured
    /// nothing *on purpose*" matters at startup: [`Planes::default`] is used
    /// by tests that want two isolated in-process endpoints, and silently
    /// giving those n0's relay map would put unit tests on the network.
    pub seeds: Option<mshr::Seeds>,
}

impl Planes {
    /// The camp-RPC lane **as actually served** — `None` when the lane is
    /// off *or* when nothing gates who reaches it.
    ///
    /// Admitting a camp-RPC dial execs `yah camp --stdio` on this
    /// machine. Under [`Admission::AllowAll`] that is remote code
    /// execution for any NodeId that can reach the endpoint, and the
    /// `--camp-rpc-root` containment is a path filter, not
    /// authentication. So the lane is withheld rather than served: an
    /// operator who has not configured admission gets a node that
    /// greets and refuses camps, not one that greets and hands out
    /// shells.
    pub fn camp_rpc_lane(&self) -> Option<&crate::camp_rpc::CampRpcConfig> {
        if self.admission.is_allow_all() {
            return None;
        }
        self.camp_rpc.as_ref()
    }

    /// Whether a configured camp-RPC lane is being withheld for want of
    /// an admission policy. Callers use this to say so out loud at
    /// startup — the silent version of this state is an operator staring
    /// at a node that advertises no camp lane they explicitly enabled.
    pub fn camp_rpc_withheld(&self) -> bool {
        self.camp_rpc.is_some() && self.admission.is_allow_all()
    }

    /// The ALPNs an endpoint must advertise to serve these lanes.
    ///
    /// Derived from the same value that builds the handler map so the
    /// two cannot drift: an advertised ALPN with no handler negotiates
    /// successfully and then drops the connection, which reads to the
    /// caller as a flaky network rather than a misconfiguration.
    pub fn alpns(&self) -> Vec<&'static [u8]> {
        let mut alpns = vec![CONTROL_PLANE_ALPN];
        if self.camp_rpc_lane().is_some() {
            alpns.push(crate::camp_rpc::CAMP_RPC_ALPN);
        }
        alpns
    }

    /// The discovery configuration to bind with — [`mshr::Seeds::none`] when
    /// none was supplied, so an unconfigured `Planes` binds exactly the
    /// endpoint it bound before R609-F4.
    pub fn seeds(&self) -> mshr::Seeds {
        self.seeds.clone().unwrap_or_else(mshr::Seeds::none)
    }
}

/// Bind the control-plane endpoint on this machine's hostkey, serving
/// only the [`CONTROL_PLANE_ALPN`] greeting.
pub async fn bind(hostkey_dir: &Path) -> Result<mshr::Endpoint> {
    bind_planes(hostkey_dir, &Planes::default()).await
}

/// Bind the control-plane endpoint on this machine's hostkey.
///
/// `hostkey_dir` is the directory [`crate::identity::generate_or_load_hostkey`]
/// wrote into — mshr's own identity file (`identity.ed25519`) lives there,
/// so [`mshr::Keypair::load_or_create_at`] loads the *same* 32 bytes and the
/// endpoint's `NodeId` is stable across restarts by construction rather
/// than by a second persistence path we'd have to keep in sync.
pub async fn bind_planes(hostkey_dir: &Path, planes: &Planes) -> Result<mshr::Endpoint> {
    let keypair = load_keypair(hostkey_dir)?;
    let mut builder = planes
        .seeds()
        .apply(mshr::Endpoint::builder())
        .keypair(keypair)
        .alpns(planes.alpns());
    // Register the hook only for a real policy. `AllowAll` is mshr's own
    // no-hook default, and leaving `Endpoint::acceptor()` `None` there
    // keeps "is anything gating this endpoint?" answerable by inspection.
    if !planes.admission.is_allow_all() {
        builder = builder.acceptor(planes.admission.clone());
    }
    builder
        .bind()
        .await
        .context("binding the mshr control-plane endpoint")
}

/// This machine's control-plane `NodeId`, without binding anything.
///
/// The admission allowlist wants the node's own `NodeId` before the
/// endpoint exists (the policy is registered *on* the builder), and an
/// operator wants it before starting the daemon at all. Same loader
/// [`bind_planes`] uses, so it cannot report an identity the endpoint
/// won't have.
pub fn node_id_at(hostkey_dir: &Path) -> Result<mshr::NodeId> {
    Ok(load_keypair(hostkey_dir)?.node_id())
}

fn load_keypair(hostkey_dir: &Path) -> Result<mshr::Keypair> {
    mshr::Keypair::load_or_create_at(hostkey_dir).with_context(|| {
        format!(
            "loading mshr machine identity at {} for the control-plane endpoint",
            hostkey_dir.display()
        )
    })
}

/// Run the control-plane accept loop until the endpoint is closed,
/// serving only the [`CONTROL_PLANE_ALPN`] greeting.
pub async fn run(endpoint: mshr::Endpoint, hello: Hello) -> Result<()> {
    run_planes(endpoint, hello, Planes::default()).await
}

/// Run the control-plane accept loop until the endpoint is closed.
///
/// Every accepted connection on [`CONTROL_PLANE_ALPN`] is answered with
/// `hello`; each enabled lane in `planes` gets its own handler on its own
/// ALPN; connections on any other ALPN are dropped by mshr's dispatcher.
///
/// "Accepted" is doing work: the [`Admission`] policy registered at
/// [`bind_planes`] runs first, and a refused `NodeId` never reaches any
/// handler here. Admission therefore has to be configured on the
/// *endpoint*, not on this call — passing a gated `planes` to a loop
/// whose endpoint was bound ungated would install lane handlers behind
/// no gate at all.
pub async fn run_planes(endpoint: mshr::Endpoint, hello: Hello, planes: Planes) -> Result<()> {
    let payload =
        Arc::new(serde_json::to_vec(&hello).context("serializing the control-plane Hello")?);

    let handler: mshr::endpoint::AlpnHandler = Arc::new(move |conn: mshr::Connection| {
        let payload = Arc::clone(&payload);
        Box::pin(async move { serve_hello(conn, payload).await })
    });

    let mut handlers: HashMap<mshr::endpoint::Alpn, mshr::endpoint::AlpnHandler> = HashMap::new();
    handlers.insert(CONTROL_PLANE_ALPN.to_vec(), handler);
    if let Some(camp_rpc) = planes.camp_rpc_lane().cloned() {
        crate::camp_rpc::install(&mut handlers, camp_rpc);
    }

    endpoint
        .accept_dispatch(handlers)
        .await
        .context("control-plane accept loop")
}

/// Answer every bidirectional stream on one connection with the greeting.
///
/// Loops rather than serving a single stream so a caller can probe more
/// than once on a connection it already paid the handshake for; returns
/// once the peer closes (which surfaces as an `accept_bi` error, the
/// normal end of a connection rather than a fault worth logging).
async fn serve_hello(conn: mshr::Connection, payload: Arc<Vec<u8>>) -> anyhow::Result<()> {
    let remote = conn.remote_id();
    tracing::debug!(remote = %remote, "control-plane connection accepted");
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        // The request half is empty today. Read (and discard) it anyway:
        // it keeps the stream well-formed for a future request framing,
        // and a peer that sends more than the cap gets an error rather
        // than an unbounded buffer on our side.
        if let Err(e) = recv.read_to_end(MAX_REQUEST_BYTES).await {
            tracing::debug!(remote = %remote, error = %e, "control-plane request read failed");
            continue;
        }
        send.write_all(&payload)
            .await
            .context("writing control-plane Hello")?;
        send.finish().context("finishing control-plane stream")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    /// The whole promise of this module: the endpoint's `NodeId` is the
    /// hostkey, so `/identity`'s `node_id` is a dialable address and not
    /// merely a fingerprint that happens to look like one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn endpoint_node_id_equals_the_hostkey_node_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let id = identity::generate_or_load_hostkey(tmp.path()).unwrap();

        let ep = bind(tmp.path()).await.unwrap();
        assert_eq!(
            ep.node_id().to_string(),
            identity::node_id_hex(&id).unwrap()
        );
        ep.close().await;
    }

    /// Restart stability — the ticket's headline verify. A second bind on
    /// the same state dir must report the same NodeId, because the key is
    /// loaded from disk rather than minted per process.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn node_id_is_stable_across_restarts() {
        let tmp = tempfile::TempDir::new().unwrap();

        let first = bind(tmp.path()).await.unwrap();
        let first_id = first.node_id();
        first.close().await;

        let second = bind(tmp.path()).await.unwrap();
        assert_eq!(second.node_id(), first_id);
        second.close().await;
    }

    /// A fresh node with no hostkey at all still binds — mshr mints the
    /// identity — and the hostkey loader then agrees with it, so the order
    /// of "bind the endpoint" vs "generate the hostkey" doesn't matter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn binding_first_still_agrees_with_the_hostkey_loader() {
        let tmp = tempfile::TempDir::new().unwrap();

        let ep = bind(tmp.path()).await.unwrap();
        let node_id = ep.node_id().to_string();
        ep.close().await;

        let id = identity::generate_or_load_hostkey(tmp.path()).unwrap();
        assert_eq!(identity::node_id_hex(&id).unwrap(), node_id);
    }

    /// End-to-end reachability: a second endpoint dials this one by
    /// `EndpointAddr` on the control-plane ALPN and reads the greeting.
    /// This is what a bound-but-unaccepted endpoint would fail.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_dialer_reads_the_hello_over_the_control_plane_alpn() {
        let server_dir = tempfile::TempDir::new().unwrap();
        let id = identity::generate_or_load_hostkey(server_dir.path()).unwrap();
        let node_id = identity::node_id_hex(&id).unwrap();

        let server = bind(server_dir.path()).await.unwrap();
        let addr = server.endpoint_addr();
        let hello = Hello::new(node_id.clone(), Some(id.hostkey_fingerprint.clone()));
        let loop_ep = server.clone();
        let accept = tokio::spawn(async move { run(loop_ep, hello).await });

        let dialer_dir = tempfile::TempDir::new().unwrap();
        let dialer = bind(dialer_dir.path()).await.unwrap();
        let conn = dialer
            .connect_alpn(addr, CONTROL_PLANE_ALPN)
            .await
            .expect("dial control plane");

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.finish().unwrap();
        let raw = recv.read_to_end(64 * 1024).await.unwrap();
        let got: Hello = serde_json::from_slice(&raw).unwrap();

        assert_eq!(got.name, "yah-yubaba");
        assert_eq!(got.node_id, node_id);
        assert_eq!(
            got.hostkey_fingerprint.as_deref(),
            Some(id.hostkey_fingerprint.as_str())
        );
        assert_eq!(got.version, crate::VERSION);

        dialer.close().await;
        server.close().await;
        accept.abort();
    }

    // ── R609-F3: admission at the listener ───────────────────────────────

    /// Bind a control-plane endpoint under `planes` and start its accept
    /// loop, returning the endpoint and its dialable address.
    async fn serving_node(
        dir: &Path,
        planes: Planes,
    ) -> (
        mshr::Endpoint,
        mshr::EndpointAddr,
        tokio::task::JoinHandle<()>,
    ) {
        let ep = bind_planes(dir, &planes).await.unwrap();
        let addr = ep.endpoint_addr();
        let hello = Hello::new(ep.node_id().to_string(), None);
        let accept = ep.clone();
        let task = tokio::spawn(async move {
            let _ = run_planes(accept, hello, planes).await;
        });
        (ep, addr, task)
    }

    /// The ticket's headline verify, refuse half: an unentitled dialer is
    /// closed at the listener. The QUIC handshake still completes — mutual
    /// authentication is what *produces* the NodeId being judged — but the
    /// greeting is never written, so nothing this node serves was reachable
    /// by an identity it does not know.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unentitled_dialer_is_refused_before_the_greeting() {
        let server_dir = tempfile::TempDir::new().unwrap();
        let planes = Planes {
            admission: Admission::entitled(Entitlement::new()),
            ..Planes::default()
        };
        let (server, addr, accept) = serving_node(server_dir.path(), planes).await;

        let dialer_dir = tempfile::TempDir::new().unwrap();
        let dialer = bind(dialer_dir.path()).await.unwrap();
        let conn = dialer
            .connect_alpn(addr, CONTROL_PLANE_ALPN)
            .await
            .expect("the handshake completes; admission runs after it");

        // No greeting: the stream either never opens or closes unread.
        let read = match conn.open_bi().await {
            Ok((mut send, mut recv)) => {
                let _ = send.finish();
                recv.read_to_end(64 * 1024).await.ok()
            }
            Err(_) => None,
        };
        assert!(
            read.is_none_or(|bytes| bytes.is_empty()),
            "a refused dialer must not receive the control-plane greeting"
        );

        dialer.close().await;
        server.close().await;
        accept.abort();
    }

    /// The admit half, over a real endpoint: allowlist the dialer's NodeId
    /// and the same dial that was refused above reads the greeting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_allowlisted_dialer_is_admitted_and_reads_the_greeting() {
        let dialer_dir = tempfile::TempDir::new().unwrap();
        let dialer = bind(dialer_dir.path()).await.unwrap();

        let server_dir = tempfile::TempDir::new().unwrap();
        let planes = Planes {
            admission: Admission::entitled(Entitlement::new().allow(dialer.node_id())),
            ..Planes::default()
        };
        let (server, addr, accept) = serving_node(server_dir.path(), planes).await;

        let conn = dialer.connect_alpn(addr, CONTROL_PLANE_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.finish().unwrap();
        let raw = recv.read_to_end(64 * 1024).await.unwrap();
        let got: Hello = serde_json::from_slice(&raw).unwrap();
        assert_eq!(got.node_id, server.node_id().to_string());

        dialer.close().await;
        server.close().await;
        accept.abort();
    }

    /// `node_id_at` must agree with what `bind_planes` will report —
    /// the allowlist's self-entry is built from it before any endpoint
    /// exists, so a drift between the two would silently refuse self-dials.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn node_id_at_matches_the_bound_endpoint() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ahead = node_id_at(tmp.path()).unwrap();
        let ep = bind(tmp.path()).await.unwrap();
        assert_eq!(ep.node_id(), ahead);
        ep.close().await;
    }

    /// The camp-RPC lane is withheld — not merely unadvertised — while
    /// nothing gates who dials, because admitting it spawns a process.
    #[test]
    fn the_camp_rpc_lane_is_withheld_until_admission_gates_it() {
        let camp_rpc = Some(crate::camp_rpc::CampRpcConfig {
            yah_bin: "yah".into(),
            roots: vec![std::path::PathBuf::from("/srv/code")],
        });

        let ungated = Planes {
            camp_rpc: camp_rpc.clone(),
            admission: Admission::AllowAll,
            ..Planes::default()
        };
        assert!(ungated.camp_rpc_lane().is_none());
        assert!(ungated.camp_rpc_withheld());
        assert_eq!(
            ungated.alpns(),
            vec![CONTROL_PLANE_ALPN],
            "a withheld lane must not be advertised either — the ALPN list \
             and the handler map derive from one accessor"
        );

        let gated = Planes {
            camp_rpc,
            admission: Admission::entitled(Entitlement::new()),
            ..Planes::default()
        };
        assert!(gated.camp_rpc_lane().is_some());
        assert!(!gated.camp_rpc_withheld());
        assert_eq!(
            gated.alpns(),
            vec![CONTROL_PLANE_ALPN, crate::camp_rpc::CAMP_RPC_ALPN]
        );
    }

    // ── R609-F4: seeds / discovery ───────────────────────────────────────

    /// The pre-F4 posture is the default, and deliberately so: an
    /// unconfigured `Planes` must bind an endpoint that talks to nobody it
    /// was not handed. Silently defaulting to n0's infrastructure would put
    /// every unit test in this file on the public network.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unconfigured_planes_bind_an_isolated_endpoint() {
        assert_eq!(Planes::default().seeds(), mshr::Seeds::none());

        let tmp = tempfile::TempDir::new().unwrap();
        let ep = bind_planes(tmp.path(), &Planes::default()).await.unwrap();
        assert!(
            !ep.resolves_bare_node_ids(),
            "an unconfigured node must not claim to be dialable by bare NodeId"
        );
        ep.close().await;
    }

    /// The headline of the ticket: configured seeds reach the endpoint, so
    /// the node becomes dialable by NodeId. Uses the LAN lane rather than the
    /// shipped defaults so the assertion does not depend on reaching n0.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn configured_seeds_make_the_node_dialable_by_bare_node_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let planes = Planes {
            seeds: Some(mshr::Seeds::none().with_lan(true)),
            ..Planes::default()
        };
        let ep = bind_planes(tmp.path(), &planes).await.unwrap();
        assert!(ep.resolves_bare_node_ids());
        ep.close().await;
    }

    /// Seeds and admission are independent axes — a gated endpoint still
    /// gets its discovery lanes, and vice versa. They are configured on the
    /// same builder, which is exactly where one can silently drop the other.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn seeds_and_admission_do_not_displace_each_other() {
        let tmp = tempfile::TempDir::new().unwrap();
        let planes = Planes {
            admission: Admission::entitled(Entitlement::new()),
            seeds: Some(mshr::Seeds::none().with_lan(true)),
            ..Planes::default()
        };
        let ep = bind_planes(tmp.path(), &planes).await.unwrap();
        assert!(ep.acceptor().is_some());
        assert!(ep.resolves_bare_node_ids());
        ep.close().await;
    }

    /// An ungated endpoint registers no acceptor hook at all, so "is
    /// anything gating this endpoint?" stays answerable by inspecting the
    /// endpoint rather than by reconstructing how it was built.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_acceptor_hook_is_registered_only_for_a_real_policy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ungated = bind_planes(tmp.path(), &Planes::default()).await.unwrap();
        assert!(ungated.acceptor().is_none());
        ungated.close().await;

        let gated = bind_planes(
            tmp.path(),
            &Planes {
                admission: Admission::entitled(Entitlement::new()),
                ..Planes::default()
            },
        )
        .await
        .unwrap();
        assert!(gated.acceptor().is_some());
        gated.close().await;
    }
}
