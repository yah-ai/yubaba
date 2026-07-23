//! R625-S1 — falsify openraft 0.9 ↔ 0.10 mixed-cluster interop on the WIRE.
//!
//! Part of R625 — annotation in oss/yubaba/crates/yubaba/src/raft/network.rs
//!
//! Why this file exists: the deployed fleet runs the `v0.8.20` tag, which pins
//! `openraft = "0.9"` and serves `POST /raft/install-snapshot`. In-tree HEAD
//! pins `openraft = "=0.10.0-alpha.30"` and serves `POST /raft/snapshot` with no
//! `install-snapshot` route at all. Any rolling upgrade therefore produces a
//! mixed 0.9/0.10 cluster for the duration of the roll.
//!
//! The spike explicitly forbids concluding anything from reading the route
//! table — R608-B11 already burned that reasoning once. So this test links BOTH
//! openraft versions simultaneously (0.10 as the normal dep, 0.9 as the renamed
//! dev-dep `openraft_09`) and does the only thing that actually settles it:
//! encodes a real 0.9 RPC body to JSON — byte-for-byte what a 0.9 leader PUTs on
//! the wire, since every yubaba raft handler is `Json<...>` — and feeds it to
//! the real 0.10 decoder, and vice versa.
//!
//! A passing assertion here is a claim about production behaviour, not a model.

use serde_json::Value;

// ── 0.9 mirror of yubaba's type config ───────────────────────────────────────
// Same D/R/NodeId/Node as `raft::YubabaRaftConfig`, declared against 0.9's macro
// so we can construct genuine 0.9 wire types. `BasicNode` is version-specific
// (each openraft carries its own), hence the mirror rather than a reuse.
//
// The alias is load-bearing: 0.9's `declare_raft_types!` expands to absolute
// `openraft::…` paths, which would otherwise resolve to the 0.10 crate and
// silently build a 0.10 type while looking like a 0.9 one. Aliasing inside a
// module pins the expansion to 0.9.
mod legacy {
    use openraft_09 as openraft;
    // 0.9's macro defaults `SnapshotData = Cursor<Vec<u8>>` and emits the bare
    // ident, so it must be nameable here.
    #[allow(unused_imports)]
    use std::io::Cursor;

    openraft::declare_raft_types!(
        pub LegacyConfig:
            D = yubaba::raft::YubabaRequest,
            R = yubaba::raft::YubabaResponse,
            NodeId = u64,
            Node = openraft::BasicNode,
    );
}
use legacy::LegacyConfig;

type NewConfig = yubaba::raft::YubabaRaftConfig;

/// Encode as a 0.9 node would put it on the wire.
fn wire<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("0.9 payload must serialize")
}

/// Assert a decode survived AND preserved meaning. `is_ok()` alone is not
/// enough: serde fills absent fields with defaults, so a struct that merely
/// *parses* can still carry a zeroed term or a dropped log id — which would
/// look like compatibility while silently corrupting an election. Comparing the
/// shared fields after a re-encode catches that.
fn assert_fields_preserved(sent: &Value, got: &Value, fields: &[&str], ctx: &str) {
    for f in fields {
        assert_eq!(
            got.get(f),
            sent.get(f),
            "{ctx}: field `{f}` did not survive the version boundary intact.\n\
             sent: {sent}\ngot:  {got}\n\
             => this is silent corruption, which is worse than a hard failure."
        );
    }
}

fn legacy_vote_request() -> openraft_09::raft::VoteRequest<u64> {
    // NOTE: in 0.9 `VoteRequest` is generic over the *NodeId*; 0.10 made it
    // generic over the whole type config. That signature churn is itself a hint
    // that the wire types were reworked, but only the round-trips below settle it.
    openraft_09::raft::VoteRequest::<u64>::new(
        openraft_09::Vote::new(1, 7),
        Some(openraft_09::LogId::new(
            openraft_09::CommittedLeaderId::new(1, 7),
            42,
        )),
    )
}

fn legacy_heartbeat() -> openraft_09::raft::AppendEntriesRequest<LegacyConfig> {
    // An empty-entries AppendEntries is the heartbeat — the most frequent RPC in
    // the cluster and the one a roll hits first, before any log shipping.
    openraft_09::raft::AppendEntriesRequest::<LegacyConfig> {
        vote: openraft_09::Vote::new_committed(1, 7),
        prev_log_id: Some(openraft_09::LogId::new(
            openraft_09::CommittedLeaderId::new(1, 7),
            42,
        )),
        entries: vec![],
        leader_commit: Some(openraft_09::LogId::new(
            openraft_09::CommittedLeaderId::new(1, 7),
            42,
        )),
    }
}

// ── direction 1: an un-upgraded 0.9 node talking to an upgraded 0.10 node ────

#[test]
fn vote_request_survives_09_to_010() {
    let on_wire = wire(&legacy_vote_request());

    let decoded = serde_json::from_value::<openraft::raft::VoteRequest<NewConfig>>(on_wire.clone())
        .unwrap_or_else(|e| {
            panic!(
                "R625-S1: a 0.9 node's VoteRequest did NOT decode on a 0.10 node.\n\
                 wire: {on_wire}\nerror: {e}\n\
                 => elections cannot cross the boundary; a rolling upgrade splits the cluster."
            )
        });

    assert_fields_preserved(
        &on_wire,
        &wire(&decoded),
        &["vote", "last_log_id"],
        "VoteRequest 0.9 -> 0.10",
    );
}

#[test]
fn append_entries_heartbeat_survives_09_to_010() {
    let on_wire = wire(&legacy_heartbeat());

    let decoded =
        serde_json::from_value::<openraft::raft::AppendEntriesRequest<NewConfig>>(on_wire.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "R625-S1: a 0.9 leader's AppendEntries heartbeat did NOT decode on a 0.10 \
                     follower.\nwire: {on_wire}\nerror: {e}\n\
                     => replication is dead across the boundary, not merely degraded."
                )
            });

    assert_fields_preserved(
        &on_wire,
        &wire(&decoded),
        &["vote", "prev_log_id", "leader_commit", "entries"],
        "AppendEntries 0.9 -> 0.10",
    );
}

// ── direction 2: the upgraded 0.10 node talking back to the 0.9 holdout ──────
// This is the direction a roll actually exercises first (upgrade one node, it
// becomes leader, it addresses the un-upgraded peers) and the riskier one: 0.10
// emits fields 0.9 has never seen, e.g. `leadership_transfer` on VoteRequest.
// If 0.9 used `deny_unknown_fields` anywhere, this is where it detonates.

#[test]
fn vote_request_survives_010_to_09() {
    // Round-trip a 0.9 request through 0.10 so the value is genuinely 0.10-built,
    // then re-encode as a 0.10 leader would transmit it.
    let via_010: openraft::raft::VoteRequest<NewConfig> =
        serde_json::from_value(wire(&legacy_vote_request())).expect("0.9 -> 0.10 already proven");
    let on_wire = wire(&via_010);

    assert!(
        on_wire.get("leadership_transfer").is_some(),
        "expected 0.10 to emit the added `leadership_transfer` field; if this \
         changed, the unknown-field risk this test guards has moved"
    );

    let decoded = serde_json::from_value::<openraft_09::raft::VoteRequest<u64>>(on_wire.clone())
        .unwrap_or_else(|e| {
            panic!(
                "R625-S1: a 0.10 leader's VoteRequest did NOT decode on a 0.9 follower.\n\
                 wire: {on_wire}\nerror: {e}\n\
                 => the un-upgraded majority cannot accept the new leader; rolling is unsafe."
            )
        });

    assert_fields_preserved(
        &on_wire,
        &wire(&decoded),
        &["vote", "last_log_id"],
        "VoteRequest 0.10 -> 0.9",
    );
}

#[test]
fn append_entries_heartbeat_survives_010_to_09() {
    let via_010: openraft::raft::AppendEntriesRequest<NewConfig> =
        serde_json::from_value(wire(&legacy_heartbeat())).expect("0.9 -> 0.10 already proven");
    let on_wire = wire(&via_010);

    let decoded = serde_json::from_value::<openraft_09::raft::AppendEntriesRequest<LegacyConfig>>(
        on_wire.clone(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "R625-S1: a 0.10 leader's AppendEntries heartbeat did NOT decode on a 0.9 \
                 follower.\nwire: {on_wire}\nerror: {e}\n\
                 => the upgraded leader cannot replicate to un-upgraded peers."
        )
    });

    assert_fields_preserved(
        &on_wire,
        &wire(&decoded),
        &["vote", "prev_log_id", "leader_commit", "entries"],
        "AppendEntries 0.10 -> 0.9",
    );
}

/// The snapshot path is the one the spike called out by name. This asserts the
/// *route-level* break as an executable fact rather than a code-reading: 0.9's
/// client posts to `/raft/install-snapshot`, and the 0.10 router has no such
/// route. Kept as a test so it fails loudly if someone re-adds the alias and
/// forgets to update W275.
#[test]
fn snapshot_route_renamed_between_09_and_010() {
    let router_src = include_str!("../src/lib.rs");

    let serves_new = router_src.contains(r#".route("/raft/snapshot""#);
    let serves_legacy = router_src.contains(r#".route("/raft/install-snapshot""#);

    assert!(
        serves_new,
        "expected the 0.10 /raft/snapshot route to exist"
    );
    assert!(
        !serves_legacy,
        "R625-S1: /raft/install-snapshot is back. If this is a deliberate \
         compatibility alias, update W275 — the mixed-version snapshot finding changes."
    );
}

// ── the real replication path, not just heartbeats ───────────────────────────
// Entries are where `storage-v2` and the LeaderId rework would actually bite:
// a heartbeat carries no payload, so it can pass while log shipping still fails.
// Membership entries are the highest-risk shape (nested node maps).

fn legacy_append_with_entries() -> openraft_09::raft::AppendEntriesRequest<LegacyConfig> {
    use openraft_09::entry::Entry;
    use openraft_09::EntryPayload;

    let at = |idx| openraft_09::LogId::new(openraft_09::CommittedLeaderId::new(1, 7), idx);

    let normal = Entry::<LegacyConfig> {
        log_id: at(43),
        payload: EntryPayload::Normal(yubaba::raft::YubabaRequest::SetMember {
            node_id: 9,
            addr: "100.64.0.9:7443".to_string(),
        }),
    };
    let membership = Entry::<LegacyConfig> {
        log_id: at(44),
        payload: EntryPayload::Membership(openraft_09::Membership::new(
            vec![[1u64, 7u64].into_iter().collect()],
            [
                (1u64, openraft_09::BasicNode::new("100.64.0.1:7443")),
                (7u64, openraft_09::BasicNode::new("100.64.0.7:7443")),
            ]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>(),
        )),
    };
    let blank = Entry::<LegacyConfig> {
        log_id: at(45),
        payload: EntryPayload::Blank,
    };

    openraft_09::raft::AppendEntriesRequest::<LegacyConfig> {
        vote: openraft_09::Vote::new_committed(1, 7),
        prev_log_id: Some(at(42)),
        entries: vec![normal, membership, blank],
        leader_commit: Some(at(42)),
    }
}

#[test]
fn log_entries_survive_09_to_010() {
    let on_wire = wire(&legacy_append_with_entries());

    let decoded =
        serde_json::from_value::<openraft::raft::AppendEntriesRequest<NewConfig>>(on_wire.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "R625-S1: real log entries (Normal + Membership + Blank) from a 0.9 leader \
                     did NOT decode on a 0.10 follower.\nwire: {on_wire}\nerror: {e}\n\
                     => log shipping breaks across the boundary even if heartbeats pass."
                )
            });

    assert_fields_preserved(
        &on_wire,
        &wire(&decoded),
        &["entries", "vote", "prev_log_id"],
        "AppendEntries+entries 0.9 -> 0.10",
    );
}

#[test]
fn log_entries_survive_010_to_09() {
    let via_010: openraft::raft::AppendEntriesRequest<NewConfig> =
        serde_json::from_value(wire(&legacy_append_with_entries()))
            .expect("0.9 -> 0.10 already proven");
    let on_wire = wire(&via_010);

    let decoded = serde_json::from_value::<openraft_09::raft::AppendEntriesRequest<LegacyConfig>>(
        on_wire.clone(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "R625-S1: real log entries from a 0.10 leader did NOT decode on a 0.9 follower.\n\
             wire: {on_wire}\nerror: {e}\n\
             => the upgraded leader cannot ship logs to un-upgraded peers."
        )
    });

    assert_fields_preserved(
        &on_wire,
        &wire(&decoded),
        &["entries", "vote", "prev_log_id"],
        "AppendEntries+entries 0.10 -> 0.9",
    );
}

/// The snapshot break is NOT merely a renamed route — so no one is tempted to
/// "fix" mixed-version rolls with a one-line alias. 0.9 streams a snapshot in
/// chunks (`{vote, meta, offset, data, done}`); 0.10 sends the whole thing as a
/// `(vote, meta, Vec<u8>)` tuple. Aliasing `/raft/install-snapshot` onto the
/// 0.10 handler would hand it a body it cannot parse. A real compat shim would
/// have to reassemble chunks — that is a project, not a route table edit.
#[test]
fn snapshot_payloads_are_structurally_incompatible() {
    let legacy_chunk = serde_json::json!({
        "vote": { "leader_id": { "term": 1, "node_id": 7 }, "committed": true },
        "meta": {
            "last_log_id": { "leader_id": { "term": 1, "node_id": 7 }, "index": 42 },
            "last_membership": { "log_id": null, "membership": { "configs": [], "nodes": {} } },
            "snapshot_id": "snap-1"
        },
        "offset": 0,
        "data": [1, 2, 3],
        "done": true
    });

    // What the 0.10 `/raft/snapshot` handler expects: a 3-tuple, i.e. a JSON array.
    let as_010_tuple = serde_json::from_value::<(
        openraft::type_config::alias::VoteOf<NewConfig>,
        openraft::type_config::alias::SnapshotMetaOf<NewConfig>,
        Vec<u8>,
    )>(legacy_chunk.clone());

    assert!(
        as_010_tuple.is_err(),
        "0.9's chunked snapshot body unexpectedly decoded as 0.10's whole-snapshot \
         tuple. If openraft converged these shapes, a compatibility alias becomes \
         viable and W275's rolling-strategy guidance should be revisited."
    );
}

/// Pin the exact 0.9 wire shapes. The interop tests above prove compatibility
/// *today*; this one makes a future openraft bump that silently reshapes the
/// wire fail loudly here rather than in production during a roll.
#[test]
fn wire_shapes_are_pinned() {
    assert_eq!(
        wire(&legacy_vote_request()),
        serde_json::json!({
            "vote": { "leader_id": { "term": 1, "node_id": 7 }, "committed": false },
            "last_log_id": { "leader_id": { "term": 1, "node_id": 7 }, "index": 42 }
        }),
        "the 0.9 VoteRequest wire shape moved — re-verify the mixed-version finding in W275"
    );
}
