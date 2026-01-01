//! HTTP-over-Tailscale raft transport.
//!
//! Each peer in the warden cluster listens for raft RPCs on its mesh IP
//! at the same port as the regular warden daemon (`:7443`).  The paths
//! `/raft/append-entries`, `/raft/vote`, and `/raft/install-snapshot`
//! are reserved for raft RPC; the rest of the warden API is unchanged.
//!
//! `WardenNetworkFactory` is the per-node factory; `WardenNetwork` is
//! the per-peer connection handle.  Both are cheaply clone-able.

use openraft::network::{RaftNetwork, RaftNetworkFactory, RPCOption};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError};
use openraft::BasicNode;

use super::WardenRaftConfig;

// ── Factory ───────────────────────────────────────────────────────────────────

/// Creates one [`WardenNetwork`] per peer.  Stateless; cheaply cloned.
#[derive(Clone, Default)]
pub struct WardenNetworkFactory;

impl RaftNetworkFactory<WardenRaftConfig> for WardenNetworkFactory {
    type Network = WardenNetwork;

    async fn new_client(&mut self, target: u64, node: &BasicNode) -> Self::Network {
        WardenNetwork {
            target,
            base_url: format!("http://{}", node.addr),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }
}

// ── Per-peer connection ───────────────────────────────────────────────────────

pub struct WardenNetwork {
    #[allow(dead_code)]
    target: u64,
    base_url: String,
    client: reqwest::Client,
}

impl WardenNetwork {
    async fn post<Req, Resp>(&self, path: &str, req: &Req) -> Result<Resp, RPCError<u64, BasicNode, RaftError<u64>>>
    where
        Req: serde::Serialize,
        Resp: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(RPCError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HTTP {status}: {body}"),
            ))));
        }

        resp.json::<Resp>()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))
    }
}

impl RaftNetwork<WardenRaftConfig> for WardenNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<WardenRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.post("/raft/append-entries", &rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        _option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        self.post("/raft/vote", &rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<WardenRaftConfig>,
        _option: RPCOption,
    ) -> Result<InstallSnapshotResponse<u64>, RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>>
    {
        // install_snapshot has a different error variant (InstallSnapshotError) so
        // we can't use the generic self.post() helper — its error is pinned to Infallible.
        let url = format!("{}/raft/install-snapshot", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&rpc)
            .send()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(RPCError::Network(NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HTTP {status}: {body}"),
            ))));
        }

        resp.json::<InstallSnapshotResponse<u64>>()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))
    }
}
