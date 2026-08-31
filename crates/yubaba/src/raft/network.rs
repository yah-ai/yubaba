//! HTTP-over-Tailscale raft transport.
//!
//! Each peer in the yubaba cluster listens for raft RPCs on its mesh IP
//! at the same port as the regular yubaba daemon (`:7443`).  The paths
//! `/raft/append-entries`, `/raft/vote`, `/raft/pre-vote`, `/raft/snapshot`,
//! and `/raft/transfer-leader-msg` are reserved for raft RPC; the rest of the
//! yubaba API is unchanged.
//!
//! The snapshot path was `/raft/install-snapshot` through openraft 0.9 and was
//! renamed with the 0.10 bump (both in commit 4a10c3d). There is deliberately no
//! back-compat alias, so 0.9 and 0.10 nodes cannot exchange snapshots in either
//! direction. R625-S1 measured that blast radius and found it narrower than it
//! sounds — vote and append-entries stay wire-compatible both ways — and its
//! findings are recorded in the annotation block below and in W275.
//!
//! The test that produced them (`tests/mixed_version_wire_interop.rs`) and the
//! `openraft_09` dev-dependency it needed are **deleted** as of R118-T9:
//! operator decision (leif, 2026-07-25) puts every node on 0.10.0-alpha.30 and
//! accepts the fleet breakage, so there is no mixed window left to characterise
//! and nothing for a 0.9 decoder to prove. Restoring the test means restoring
//! the dev-dep; the findings it produced stand on their own.
//!
//! `YubabaNetworkFactory` is the per-node factory; `YubabaNetwork` is
//! the per-peer connection handle.  Both are cheaply clone-able.
//!
//! @yah:ticket(R593-T7, "Raft/mesh RPC transport adoption on mshr::Endpoint (R277 roadmap, renamed target) — blocked-linked, do not implement around")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-22T19:49:31Z)
//! @yah:phase(P5)
//! @yah:parent(R593)
//! @yah:depends_on(R277)
//! @yah:depends_on(R593-T1)
//! @yah:tier(Wizard)
//! @yah:next("STILL PARKED — re-verified 2026-07-22. R277 (backlog, Q273; annotated at oss/yubaba/crates/yubaba/src/raft/mod.rs:13) is the SOLE live gate and is not clearable now: it is a Tier-4 relay itself gated on Tier-3 (a real workload runtime to host raft). CAUTION: 'R277-F3' is a next-BULLET on R277, not a filed ticket — R277 has zero children on both the MCP index and a fresh `yah board show R277 --tree` scan. When that F3 work (consume mshr::Endpoint as yubaba control-plane transport) lands, replace the HTTP-over-Tailscale YubabaNetwork/YubabaNetworkFactory in THIS file with a mshr QUIC transport; W268's claim that 'the mTLS thin spot dissolves as a workstream' then becomes testable — mutual machine auth intrinsic to the transport, phase-1 plaintext-behind-Headscale-ACLs posture retired. Until R277 clears: no scaffolding, no parallel transport, no interim mTLS bolt-on.")
//! @yah:next("DEP HISTORY (settled, do not re-litigate): the R570 gate was removed 2026-07-21 and independently re-verified — R570 was never filed (absent from the live board AND all 176 archive shards, so board silently dropped it from blocked-by), and its substance shipped anyway: N-voter founding membership via POST /raft/initialize (raft_initialize handler lib.rs:3756, route lib.rs:1132, self-labeled R570-F1), openraft 0.10 native Trigger::transfer_leader with a green un-ignored 3-node loopback e2e (tests/raft_transfer_leader.rs, R608-B11), and 3 voter-candidates on the fleet (tag:voter-candidate in .yah/infra/machines). Satisfied-in-fact, so removed rather than back-filed. A dangling R570 dep still sits on leader.rs:29 under R591 — peer-owned, deliberately NOT touched.")
//! @yah:cleanup("A026-xlb-net.md still carries the pre-promotion name and describes xlb-net 0.1 (4 files reference the A026-xlb-net path: raft/mod.rs, W268, and 2 others). Renaming the arch doc + rewriting its body to the mshr design is real doc work and an arch-canon naming call — not folded into this parked ticket. Until it happens, read A026 as the mshr design doc.")
//! @yah:verify("Scope met: R277's F3 roadmap bullet (oss/yubaba/crates/yubaba/src/raft/mod.rs:19) names mshr::Endpoint with the promotion provenance inline — confirm with `yah board show R277`. The binding this ticket existed to create is in place and machine-readable.")
//! @yah:handoff("COMPLETE AS SCOPED (2026-07-22, Ashguard/dove). This ticket's stated deliverable was to BIND wave 2 to the R277 roadmap at the renamed target — explicitly 'not to start it'. That binding is now done: R277's F3 bullet (oss/yubaba/crates/yubaba/src/raft/mod.rs:19) read 'consume xlb-net::Endpoint ... (xlb-net 0.1 published)', naming a crate path that stopped existing when W268 wave 2 promoted it; it now names mshr::Endpoint at oss/mshr/crates/mshr (`pub use endpoint::Endpoint`, src/lib.rs:28) with the rename provenance inline. R277's picker-upper is no longer sent to a dead path. mod.rs was clean in git at edit time (no peer WIP); the edit is doc-comment-only so it cannot affect compilation.")
//! @yah:handoff("WHY THIS IS NOT STILL PARKED ON R277: the R277 gate governs the transport IMPLEMENTATION (replacing the HTTP-over-Tailscale YubabaNetwork/YubabaNetworkFactory in network.rs with a mshr QUIC transport) — that work is R277-F3's, not this ticket's. Conflating the two is what kept T7 parked across two prior sessions with the binding itself already achievable in minutes. The implementation instruction is preserved where it belongs: on R277's F3 bullet. Do NOT re-file this as a blocked ticket.")
//! @yah:handoff("The 2026-07-21 verification of the R570 dep-correction stands and is folded into @yah:next. Tree anchor: 7e945040ed37afe1a6cfdd0f1cb32d0ac23fd3cb — quote this SHA, not 'HEAD', in any revert instruction.")
//! @yah:next("EFFICIENCY SCOPE for whoever unparks this (measured 2026-08-02, read-only ps/free over ssh): tailscaled is the single largest process on every cloud node — 85.2 MB RSS on us-west-001, 83.9 MB on us-south-001, 83.4 MB on us-east-001 — against yubaba at 32-57 MB and passway at 13 MB. On us-south-001 (Vultr 1 vCPU / 1 GB, 961 MB usable, 570 MB available) that is ~9% of RAM for the mesh datapath, and tailscale on Linux runs wireguard-go in userspace over a TUN device, so mesh packet crypto is Go-userspace CPU too. The QUIC move is therefore a memory/CPU story as well as an auth story.")
//! @yah:next("ASK TO ANSWER BEFORE THE MOVE LANDS, not after: once yubaba<->yubaba RPC is on mshr QUIC, what still REQUIRES the tailnet? Known remaining users today are (a) workload-to-workload traffic bound to mesh IPs (the compose recipes / pg_hba + ufw snippets in mesh_service.rs) and (b) ssh control-plane rolls. If those are the only two, the control plane keeps paying tailscaled's full cost for a datapath it no longer uses, AND every mshr dial that picks a 100.64/10 direct addr is QUIC-TLS nested inside WireGuard — encrypted twice for one hop. Not an argument to drop the tailnet (MagicDNS, ACLs, NAT traversal, key rotation are why Headscale is there); an argument to decide deliberately which lanes keep it rather than inheriting both layers by default.")
//! @yah:assumes("Encrypt-exactly-once-per-hop is the intended fleet posture. Already load-bearing elsewhere: PASSWAY_UPSTREAM_TLS defaults false with the reason written in the source as 'mesh is already encrypted' (oss/passway/crates/passway/src/main.rs:31), and yubaba's control HTTP on :7443 is plaintext behind the tailnet by the same logic.")
//!
//! @yah:ticket(R625-S1, "Falsify openraft 0.9<->0.10 mixed-cluster interop before the first live roll")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-22T18:57:11Z)
//! @yah:kind(spike)
//! @yah:parent(R625)
//! @yah:gotcha("Reading the route tables is NOT sufficient evidence. R608-B11 already showed this class of reasoning failing: the Option-B trigger-elect design looked correct on paper and was only falsified by an e2e cluster test (the leader-lease made it return 504).")
//! @arch:see(.yah/docs/working/W275-rolling-upgrade-envelope.md)
//! @yah:handoff("FALSIFIED, WITH A TEST (2026-07-22, Ashguard/dove). VERDICT: mixed openraft 0.9/0.10 is **partially compatible**, NOT categorically broken — so this is NOT the stop-the-world release blocker the ticket feared, but it does carry one specific bounded hazard. Evidence is 9 green tests in oss/yubaba/crates/yubaba/tests/mixed_version_wire_interop.rs, which links BOTH openraft versions at once (0.10 normally + 0.9 as renamed dev-dep `openraft_09`) and round-trips real payloads. Every yubaba raft handler is axum `Json<...>`, so serde_json of openraft's types IS the wire format — this measures production bytes, not a model.")
//! @yah:handoff("WHAT WORKS (both directions, semantically, not just 'it parsed'): VoteRequest, AppendEntries heartbeats, and AppendEntries carrying REAL entries — Normal(YubabaRequest::SetMember) + Membership(2-voter config with BasicNode addrs) + Blank. Assertions compare field-by-field after re-encode rather than checking is_ok(), because serde defaults absent fields and a struct that merely parses can still carry a zeroed term or dropped log id — that silent-corruption path is explicitly tested against. 0.10 adds `leadership_transfer` to VoteRequest; 0.9 tolerates it as an unknown field, and 0.9's omission defaults cleanly on 0.10. So replication and elections DO cross the version boundary intact.")
//! @yah:handoff("WHAT IS BROKEN (both directions): snapshot transfer. 0.9 posts /raft/install-snapshot, which does not exist on 0.10 (404); 0.10 posts /raft/snapshot, which does not exist on 0.9 (404). There is no alias. AND — the part that matters for anyone tempted by a cheap fix — this is NOT merely a renamed route: 0.9 streams snapshots CHUNKED ({vote, meta, offset, data, done}) while 0.10 sends the whole snapshot as a (vote, meta, Vec<u8>) tuple. Aliasing the path would hand the 0.10 handler a body it cannot parse; a real shim must reassemble chunks. Test `snapshot_payloads_are_structurally_incompatible` pins this so the alias idea can't be re-proposed from a code-reading.")
//! @yah:handoff("PRACTICAL BLAST RADIUS: during a roll, a follower that is merely behind catches up via append-entries, which works — so a short roll of caught-up nodes replicates normally. The failure is narrow and specific: a peer far enough behind that the leader must send a SNAPSHOT instead of log entries cannot catch up while the cluster is mixed (e.g. a node that was down long enough for log truncation). Guidance for W275: a rolling strategy is viable, gated on 'no peer needs a snapshot during the mixed window' — keep the window short and verify no voter is log-truncated behind before starting. It does NOT require the stop-the-world strategy across the board.")
//! @yah:handoff("ONE FACT I COULD NOT RESOLVE FROM THE REPO, and it is load-bearing: whether the DEPLOYED fleet is actually on 0.9 or 0.10. The `v0.8.20` tag (Jul 17 17:47) pins openraft 0.9 and serves /raft/install-snapshot. Commit 4a10c3d (Jul 17 21:01, 3h AFTER the tag) bumped to 0.10.0-alpha.30 AND renamed the route in the SAME commit. Both call themselves 'yubaba 0.8.20', and .yah/infra/machines/*.toml records only the version string — no build SHA — so the 2026-07-21 roll ('fleet uniform on 0.8.20 across both raft voters') is ambiguous between the two. I did NOT probe the live nodes: that is production access and the operator's call. Cheapest resolution is one read-only request to a voter discriminating /raft/snapshot vs /raft/install-snapshot (404 vs 405). NOTE this ambiguity is precisely what R625-F4 (expose cluster_protocol + state_epoch on GET /health) exists to eliminate — treat this as field evidence for that ticket.")
//! @yah:handoff("ALSO FIXED IN PASS: oss/yubaba/crates/yubaba/src/raft/network.rs:5 module doc still documented the reserved RPC path as `/raft/install-snapshot` while the code posts `/raft/snapshot` (network.rs:171) — a stale doc disproved by this work. Rewrote it with the rename provenance and a pointer to the interop test. Tree anchor: 7e945040ed37afe1a6cfdd0f1cb32d0ac23fd3cb.")
//! @yah:verify("cd oss/yubaba && cargo test -p yubaba --test mixed_version_wire_interop  # 9 passed, 0 failed")
//! @yah:verify("W275 §'ANSWERED (R625-S1)' now carries the compatibility matrix and the revised strategy guidance; the old 'Open question this raises about the current fleet' section is gone.")
//! @yah:next("OPERATOR ACTION, 2 minutes, unblocks the roll decision: determine which openraft the live voters actually run. One read-only request per voter discriminating /raft/snapshot (405 on 0.10, 404 on 0.9) from /raft/install-snapshot (404 on 0.10, 405 on 0.9). Not done here — production access is the operator's call. If the fleet is ALREADY on 0.10, the mixed window is behind us and the snapshot hazard never applies to this roll.")
//! @yah:next("R625-F5 (executor preflight) can now encode a concrete predicate instead of a blanket denial: allow the rolling strategy for a 0.9->0.10 roll GATED on 'no voter is log-truncated behind' (i.e. every peer is close enough that catch-up uses append-entries, never a snapshot), plus a short mixed window. Deny/escalate only when that predicate fails.")
//! @yah:next("R625-F4 (cluster_protocol + state_epoch on GET /health) has fresh field evidence: this spike could not tell 0.9 from 0.10 on the deployed fleet because both builds call themselves 'yubaba 0.8.20' and no build SHA is recorded in .yah/infra/machines/*.toml. Cite that in the ticket — it is the concrete failure the epoch work prevents.")
//! @yah:next("OPTIONAL, only if a long mixed window is ever needed: a real snapshot compat shim (0.9 chunked {vote,meta,offset,data,done} -> 0.10 whole-snapshot tuple, reassembling chunks server-side). Explicitly NOT a route alias — tests/mixed_version_wire_interop.rs::snapshot_payloads_are_structurally_incompatible pins why. Almost certainly not worth building; prefer the short-window + no-truncated-peer gate above.")

use std::future::Future;
use std::io::Cursor;
use std::time::Duration;

use openraft::error::{
    NetworkError, RPCError, RaftError, ReplicationClosed, StreamingError, Unreachable,
};
use openraft::network::v2::RaftNetworkV2;
use openraft::network::{RPCOption, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, SnapshotResponse, TransferLeaderRequest,
    TransferLeaderResponse, VoteRequest, VoteResponse,
};
use openraft::type_config::alias::{SnapshotOf, VoteOf};
use openraft::{BasicNode, OptionalSend};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::YubabaRaftConfig as TC;

// ── Factory ───────────────────────────────────────────────────────────────────

/// Creates one [`YubabaNetwork`] per peer.  Stateless; cheaply cloned.
#[derive(Clone, Default)]
pub struct YubabaNetworkFactory;

impl RaftNetworkFactory<TC> for YubabaNetworkFactory {
    type Network = YubabaNetwork;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        YubabaNetwork {
            target,
            base_url: format!("http://{}", node.addr),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }
}

// ── Per-peer connection ───────────────────────────────────────────────────────

pub struct YubabaNetwork {
    #[allow(dead_code)]
    target: u64,
    base_url: String,
    client: reqwest::Client,
}

impl YubabaNetwork {
    /// POST `req` as JSON to `path` and hand back the peer's raw response,
    /// whatever its status. Connection failures map to [`Unreachable`] (so
    /// openraft backs off rather than hot-looping); other transport failures map
    /// to [`NetworkError`].
    ///
    /// Split out of [`Self::request`] so [`RaftNetworkV2::pre_vote`] can see a
    /// bare `404` — a peer whose build predates the `/raft/pre-vote` route — as
    /// distinct from every other kind of failure, instead of having it collapsed
    /// into an opaque `NetworkError` string it would have to sniff.
    async fn post<Req: Serialize>(
        &self,
        path: &str,
        req: Req,
        option: &RPCOption,
    ) -> Result<reqwest::Response, RPCError<TC>> {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .json(&req)
            .timeout(option.soft_ttl())
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    RPCError::Unreachable(Unreachable::new(&e))
                } else {
                    RPCError::Network(NetworkError::new(&e))
                }
            })
    }

    /// Decode a peer's `Result<Resp, RaftError>` reply. A non-2xx status is a
    /// [`NetworkError`]; a remote raft-level error is surfaced as `Unreachable`,
    /// matching the openraft v2 HTTP example.
    async fn decode<Resp>(&self, path: &str, resp: reqwest::Response) -> Result<Resp, RPCError<TC>>
    where
        Result<Resp, RaftError<TC>>: DeserializeOwned,
    {
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(RPCError::Network(NetworkError::from_string(format!(
                "HTTP {status} from {}{path}: {body}",
                self.base_url
            ))));
        }

        let res: Result<Resp, RaftError<TC>> = resp
            .json()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        res.map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))
    }

    /// POST `req` as JSON to `path` and decode the peer's `Result<Resp,
    /// RaftError>` reply.
    async fn request<Req, Resp>(
        &self,
        path: &str,
        req: Req,
        option: &RPCOption,
    ) -> Result<Resp, RPCError<TC>>
    where
        Req: Serialize,
        Result<Resp, RaftError<TC>>: DeserializeOwned,
    {
        let resp = self.post(path, req, option).await?;
        self.decode(path, resp).await
    }
}

impl RaftNetworkV2<TC> for YubabaNetwork {
    type SnapshotData = Cursor<Vec<u8>>;

    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TC>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<TC>, RPCError<TC>> {
        self.request("/raft/append-entries", rpc, &option).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<TC>,
        option: RPCOption,
    ) -> Result<VoteResponse<TC>, RPCError<TC>> {
        self.request("/raft/vote", rpc, &option).await
    }

    /// Ask the peer whether it *would* grant a vote at `rpc.vote` — R734-T1.
    ///
    /// Without this method the trait's default implementation synthesizes a
    /// grant, which makes `enable_pre_vote` inert: a pre-candidate collects a
    /// fabricated quorum and campaigns exactly as it would have with Pre-Vote
    /// off. So the flag in
    /// [`RaftTiming::to_openraft_config`](crate::cluster_policy::RaftTiming::to_openraft_config)
    /// and this method are one change, not two.
    ///
    /// # Why a 404 is a grant and a dead socket is not
    ///
    /// openraft counts only `Ok(granted)` toward the Pre-Vote quorum; an `Err`
    /// is never a grant, deliberately, so that a fully isolated node cannot
    /// synthesize a quorum out of its own unreachable peers and inflate the
    /// term. That rule is what makes the 404 case a *different* case: a peer
    /// that answers `404` answered — it is reachable, its raft is running, its
    /// build simply predates this route. Treating that as a grant is exactly
    /// the "network has not implemented `pre_vote`" degrade the trait's default
    /// impl provides, and it is what keeps a mixed-version cluster live: during
    /// a roll, a new node's Pre-Vote to an old peer must not be able to strand
    /// the cluster leaderless because the old peer has no route to answer on.
    /// A connect failure still returns `Err`, so the isolated-node protection
    /// is untouched.
    ///
    /// This is why the change needs no `cluster_protocol` bump: an old node
    /// never sends Pre-Vote, and a new node's Pre-Vote to an old node degrades
    /// to the pre-R734-T1 behaviour rather than failing.
    async fn pre_vote(
        &mut self,
        rpc: VoteRequest<TC>,
        option: RPCOption,
    ) -> Result<VoteResponse<TC>, RPCError<TC>> {
        let candidate_vote = rpc.vote;
        let resp = self.post("/raft/pre-vote", rpc, &option).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(VoteResponse::new(candidate_vote, None, true));
        }
        self.decode("/raft/pre-vote", resp).await
    }

    /// Stream a full snapshot to the peer in one shot. Yubaba snapshots are
    /// KB-scale JSON, so the whole `(vote, meta, bytes)` payload rides a single
    /// POST — the target reconstructs the [`Snapshot`](openraft::Snapshot) and
    /// calls `install_full_snapshot`. `cancel` aborts a mid-flight transfer.
    async fn full_snapshot(
        &mut self,
        vote: VoteOf<TC>,
        snapshot: SnapshotOf<TC, Self::SnapshotData>,
        cancel: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        option: RPCOption,
    ) -> Result<SnapshotResponse<TC>, StreamingError<TC>> {
        let req = (vote, snapshot.meta, snapshot.snapshot.into_inner());
        tokio::pin!(cancel);

        tokio::select! {
            closed = &mut cancel => Err(StreamingError::Closed(closed)),
            res = self.request("/raft/snapshot", req, &option) => Ok(res?),
        }
    }

    /// Deliver a TransferLeader message to the target (R608-B11). The target
    /// passes it to `Raft::handle_transfer_leader`, which lets it campaign at
    /// once — the openraft-native handoff that bypasses the leader lease.
    async fn transfer_leader(
        &mut self,
        req: TransferLeaderRequest<TC>,
        option: RPCOption,
    ) -> Result<TransferLeaderResponse<TC>, RPCError<TC>> {
        self.request("/raft/transfer-leader-msg", req, &option)
            .await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// R734-T1 — the three outcomes a Pre-Vote RPC can have, pinned against a real
/// HTTP peer rather than against a mock of one.
///
/// The distinction being defended: openraft counts only `Ok(granted)` toward the
/// Pre-Vote quorum, so *what we turn a failure into* decides whether Pre-Vote
/// protects the cluster or strands it. Answering `404` (an old build) must grant;
/// refusing to connect (a partitioned peer) must not. Getting those two the same
/// way round is the bug this suite exists to catch, and it is invisible to a
/// test that only checks the happy path.
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::routing::post;
    use axum::{Json, Router};
    use openraft::raft::{VoteRequest, VoteResponse};

    use super::*;

    /// A vote at term 7 from node 2 — the hypothetical `term + 1` a
    /// pre-candidate probes with.
    fn candidate_vote() -> VoteOf<TC> {
        VoteOf::<TC>::new(7, 2)
    }

    /// Serve `router` on loopback and return a [`YubabaNetwork`] pointed at it.
    /// The server task is detached; it dies with the test runtime.
    async fn network_against(router: Router) -> YubabaNetwork {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        YubabaNetworkFactory
            .new_client(2, &BasicNode::new(addr.to_string()))
            .await
    }

    /// A peer whose build predates `/raft/pre-vote` answers 404 — and that must
    /// count as a grant, or a Pre-Vote-enabled node cannot assemble a quorum
    /// during a rolling upgrade and the cluster stays leaderless.
    #[tokio::test]
    async fn a_404_from_a_pre_r734_peer_counts_as_a_grant() {
        // Deliberately a router with no /raft/pre-vote route at all: this is the
        // shape of an older yubaba, not a stub that returns a canned 404.
        let mut net =
            network_against(Router::new().route("/raft/vote", post(|| async { "" }))).await;

        let resp = net
            .pre_vote(
                VoteRequest::new(candidate_vote(), None),
                RPCOption::new(Duration::from_secs(5)),
            )
            .await
            .expect("a 404 must not surface as a transport error");

        assert!(
            resp.is_granted_to(&candidate_vote()),
            "a reachable peer with no pre-vote route must degrade to a grant: {resp:?}"
        );
    }

    /// A peer that *does* implement the route and says no must be reported as a
    /// refusal. Without this, a fallback written slightly too broadly (catching
    /// every non-2xx, say) would turn every honest refusal into a grant and
    /// silently disable Pre-Vote across the whole cluster.
    #[tokio::test]
    async fn a_real_refusal_survives_the_404_fallback() {
        let router = Router::new().route(
            "/raft/pre-vote",
            post(|Json(req): Json<VoteRequest<TC>>| async move {
                Json(Ok::<_, RaftError<TC>>(VoteResponse::<TC>::new(
                    req.vote, None, false,
                )))
            }),
        );
        let mut net = network_against(router).await;

        let resp = net
            .pre_vote(
                VoteRequest::new(candidate_vote(), None),
                RPCOption::new(Duration::from_secs(5)),
            )
            .await
            .expect("a served refusal is a successful RPC");

        assert!(
            !resp.vote_granted,
            "a peer that refuses must be reported as refusing, not rewritten into a grant: \
             {resp:?}"
        );
    }

    /// An unreachable peer must be an `Err`, never a grant. This is the
    /// protection openraft's own docs call out: a fully isolated node that
    /// synthesized grants from its dead peers would assemble a quorum of one,
    /// campaign, and inflate the term — defeating the entire feature.
    #[tokio::test]
    async fn an_unreachable_peer_is_an_error_not_a_grant() {
        // Bind then drop, so the port is one nothing is listening on.
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            listener.local_addr().expect("local addr")
        };
        let mut net = YubabaNetworkFactory
            .new_client(2, &BasicNode::new(addr.to_string()))
            .await;

        let res = net
            .pre_vote(
                VoteRequest::new(candidate_vote(), None),
                RPCOption::new(Duration::from_secs(2)),
            )
            .await;

        assert!(
            res.is_err(),
            "an unreachable peer must not be counted as granting a pre-vote: {res:?}"
        );
    }
}
