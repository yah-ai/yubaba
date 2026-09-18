//! The raft core `yubaba` is built on, extracted so a node can link consensus
//! without linking the fleet daemon (noisetable R118-T11, `W138` "Installation as a
//! cluster", `A111` §budget).
//!
//! # Why this crate exists
//!
//! `yubaba`'s library crate is the *fleet daemon*: ~40 HTTP routes bound to pond
//! deploy, litestream replication, secret reload, the cheers client and the
//! ACME issuer. A gallery plinth running three boxes on a power strip wants none
//! of that and should not compile or link it — but it does want exactly what is
//! in here: a replicated state machine, a leader, a lock, and a placement
//! decision.
//!
//! The split follows the grain rather than cutting across it. `cloud`,
//! `hetzner`, `floating-ip`, `almanac`, `kamaji` and `yubaba-client` were
//! already separate crates; the monolith was specifically the daemon crate, and
//! consensus is the piece with no fleet-specific dependencies. That is not an
//! assertion — it is checked by this crate's dependency list, which is openraft,
//! serde, reqwest, tokio, tracing and `workload-spec`, and by the fact that
//! nothing here says the words pond, litestream, acme or cheers.
//!
//! # What is in, and the one seam that was cut
//!
//! - [`raft`] — the `YubabaState` / `YubabaRequest` state machine, its openraft
//!   log store (`raft::store`) and the HTTP `RaftNetworkV2` factory
//!   (`raft::network`). The raft transport genuinely is HTTP, which is why
//!   `reqwest` is a dependency of a consensus crate rather than a smell.
//! - [`cluster_policy`] — the declarative shape of a cluster (`ClusterPolicy`):
//!   quorum geography, raft timings, voter admission, ingress ownership and the
//!   membership-ratchet mode. Deliberately **not** feature-gated: policy is a
//!   runtime value (R118-T9), so a build that cannot express `Frozen` is a build
//!   that cannot read another cluster's config.
//! - [`membership_ratchet`] — `plan` / `plan_rehydrate`, the pure functions that
//!   shrink a voter set while quorum still holds and grow it back through
//!   learners with hysteresis. This is the rig's most rig-specific behaviour and
//!   so it belongs on *this* side of the seam, not the daemon's.
//!
//! The seam that had to be cut is [`membership_ratchet::OriginSource`]. Judging a
//! joiner's lineage is pure and stayed here as
//! [`membership_ratchet::judge_origin`]; *fetching* that lineage means two GETs
//! against `/raft/status` and `/health`, and `/health` is a route the fleet
//! daemon defines and owns. A consensus crate that hard-codes another crate's
//! route schema has not been extracted, so the fetch is a caller-supplied port
//! and `yubaba` implements it (`yubaba::origin_source::HttpOriginSource`).
//!
//! # What stayed in the daemon, and why
//!
//! - **Routes.** `POST /raft/add-learner`, `POST /v1/nodes/{id}/peer-liveness`
//!   and the other `/raft/*` handlers are HTTP surface; they live in `yubaba`.
//!   The request and state *types* they carry live here.
//! - **`cluster_epoch`.** `CLUSTER_PROTOCOL` / `STATE_EPOCH` are `include_str!`d
//!   out of `crates/yubaba/cluster-epochs.json`, which the xtask drift gate and
//!   the release manifest both read by path. Moving the module would move that
//!   file out from under two consumers outside this ticket's blast radius for no
//!   gain: the values reach consensus as data, through
//!   [`membership_ratchet::LocalLineage`], which is the right shape anyway.
//!
//! The design docs this answers to live in the NOISETABLE camp, not this repo,
//! so they are named rather than linked with `@arch:see` (which this repo's
//! scanner would resolve against its own tree and find nothing):
//! `.yah/docs/working/W138-installation-as-a-cluster.md` and
//! `.yah/docs/architecture/A111-embedded-headless-audio-node.md`.

pub mod cluster_policy;
pub mod membership_ratchet;
pub mod raft;

/// Wall-clock seconds since the Unix epoch, saturating to 0 on a pre-epoch
/// clock rather than panicking.
///
/// This is the timestamp every replicated record here is stamped with
/// (`MembershipRatchetRecord::at`, the ratchet loop's tick `now`), so it lives
/// at the crate root rather than beside one caller. noisetable R118-T11 moved it down from
/// `yubaba::rollout`, which was where the daemon happened to define it first;
/// `yubaba::rollout::now_unix_secs` is now a re-export of this, so the two
/// cannot drift into disagreeing about what "now" is on the same node.
///
/// Deliberately NOT a monotonic clock: these values are compared across nodes
/// and written into raft, where a monotonic reading is meaningless. Hysteresis
/// that must survive a clock step belongs in the detector, which uses
/// `Instant` — see `yubaba::lease_detector`.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
