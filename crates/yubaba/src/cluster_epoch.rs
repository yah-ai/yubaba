//! The two cluster-compatibility epochs this build declares (W275 "Cluster
//! compatibility epochs", R625-F2).
//!
//! `yubaba`'s crate version cannot carry the claim "these two builds may not sit
//! in one raft cluster simultaneously": that is a property of a *pair* of builds
//! and of an *internal* surface whose lifecycle is independent of the product
//! version. The openraft 0.9→0.10 migration is the proof — the product version
//! moved 0.8.18 → 0.8.20 (a patch-looking bump) while the raft snapshot route
//! and payload changed underneath.
//!
//! So each build declares two **monotonic integers**, and mixed operation is
//! permitted iff every node shares them:
//!
//! - [`CLUSTER_PROTOCOL`] — **wire**: may node A talk to node B mid-roll.
//! - [`STATE_EPOCH`] — **on-disk**: can this binary read the previous binary's
//!   raft log/snapshot, and can you roll *back* to it.
//!
//! They are deliberately **separate**. openraft 0.9→0.10 broke both at once,
//! which is exactly why a single flag would have hidden the rollback hazard: a
//! roll that half-migrates on-disk state and then cannot roll back makes W275
//! §5 "Roll-back is symmetric" quietly false.
//!
//! # Single source of truth
//!
//! The numbers live in [`cluster-epochs.json`](../cluster-epochs.json) next to
//! this crate's manifest, **not** in this file. That JSON is the one artifact
//! both halves of the system read:
//!
//! - this module `include_str!`s it and parses it at *compile time*, so the
//!   running binary and `GET /health` (R625-F4) report what the file says;
//! - `.github/workflows/release.yml` reads it with `jq` when it merges the
//!   per-triple fragments into the signed `release-manifest.json`, so the
//!   published manifest carries the same two integers (R625-F2).
//!
//! Because there is exactly one file, the manifest cannot drift from the
//! binary. What the file cannot do on its own is prove the numbers are *right* —
//! that a protocol change was accompanied by a bump. That is R625-F3's job:
//! derive the epoch in CI from a hash of the protocol surface and fail the build
//! when the hash moves and the epoch did not.
//!
//! Part of R625-F2 — annotation in `app/yah/cli/src/rollout/apply.rs`.

/// The raw declaration file. Parsed at compile time by [`declared_u32`]; a
/// malformed or incomplete file is a **build failure**, not a runtime surprise.
const EPOCHS_JSON: &str = include_str!("../cluster-epochs.json");

/// Wire-compatibility epoch. Bumped iff the mixed-operation contract broke —
/// i.e. a build at epoch N cannot serve/consume the raft RPC surface of a build
/// at any other epoch. Two nodes may sit in one cluster iff these are equal.
pub const CLUSTER_PROTOCOL: u32 = declared_u32(EPOCHS_JSON, "\"cluster_protocol\":");

/// On-disk state epoch. Bumped iff the durable raft log/snapshot layout changed
/// such that a binary at a different epoch cannot read it. A mismatch means the
/// roll is **not** reversible, which is the dangerous axis.
pub const STATE_EPOCH: u32 = declared_u32(EPOCHS_JSON, "\"state_epoch\":");

/// Extract the decimal integer that follows `needle` in `src`.
///
/// A deliberately tiny const-evaluable scanner rather than a JSON parser: it
/// runs at compile time, so `cluster-epochs.json` cannot be missing a key or
/// carry a non-integer value in a binary that built. `needle` includes both the
/// closing quote and the colon (`"state_epoch":`), which is what keeps the
/// sibling `"state_epoch_history"` documentation key from matching.
const fn declared_u32(src: &str, needle: &str) -> u32 {
    let s = src.as_bytes();
    let n = needle.as_bytes();
    if n.len() == 0 || s.len() < n.len() {
        panic!("cluster-epochs.json: file is too short to contain the requested key");
    }
    let mut i = 0;
    while i + n.len() <= s.len() {
        let mut j = 0;
        while j < n.len() && s[i + j] == n[j] {
            j += 1;
        }
        if j == n.len() {
            let mut k = i + n.len();
            while k < s.len() && (s[k] == b' ' || s[k] == b'\t' || s[k] == b'\n' || s[k] == b'\r') {
                k += 1;
            }
            let start = k;
            let mut value: u32 = 0;
            while k < s.len() && s[k] >= b'0' && s[k] <= b'9' {
                value = value * 10 + (s[k] - b'0') as u32;
                k += 1;
            }
            if k == start {
                panic!(
                    "cluster-epochs.json: key is present but its value is not a decimal integer"
                );
            }
            return value;
        }
        i += 1;
    }
    panic!("cluster-epochs.json: required epoch key not found");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_epochs_are_nonzero() {
        // 0 is the "never declared" sentinel a hand-rolled default would produce;
        // a real declaration starts at 1.
        assert!(CLUSTER_PROTOCOL >= 1, "cluster_protocol must be >= 1");
        assert!(STATE_EPOCH >= 1, "state_epoch must be >= 1");
    }

    #[test]
    fn declared_epochs_match_the_json_at_runtime() {
        // The compile-time scanner and a real JSON parser must agree — this is
        // what lets release.yml read the same file with `jq` and get the same
        // numbers the binary reports on /health.
        let parsed: serde_json::Value = serde_json::from_str(EPOCHS_JSON).unwrap();
        assert_eq!(
            parsed["cluster_protocol"].as_u64().unwrap() as u32,
            CLUSTER_PROTOCOL
        );
        assert_eq!(parsed["state_epoch"].as_u64().unwrap() as u32, STATE_EPOCH);
    }

    #[test]
    fn every_declared_epoch_has_a_history_entry() {
        // The history block is how a future reader learns *why* an epoch moved.
        // An undocumented bump is a bump nobody can audit.
        let parsed: serde_json::Value = serde_json::from_str(EPOCHS_JSON).unwrap();
        for (key, current) in [
            ("cluster_protocol", CLUSTER_PROTOCOL),
            ("state_epoch", STATE_EPOCH),
        ] {
            let history = parsed[format!("{key}_history")]
                .as_object()
                .unwrap_or_else(|| panic!("{key}_history missing"));
            for epoch in 1..=current {
                assert!(
                    history.contains_key(&epoch.to_string()),
                    "{key}_history has no entry for epoch {epoch}"
                );
            }
        }
    }

    #[test]
    fn scanner_reads_the_value_after_the_key() {
        assert_eq!(declared_u32(r#"{"a": 7}"#, "\"a\":"), 7);
        assert_eq!(declared_u32("{\"a\":\n  42 }", "\"a\":"), 42);
    }

    #[test]
    fn scanner_does_not_match_a_longer_sibling_key() {
        // `"state_epoch_history"` must not satisfy a lookup for `"state_epoch"`.
        let src = r#"{"state_epoch_history": {"1": "x"}, "state_epoch": 3}"#;
        assert_eq!(declared_u32(src, "\"state_epoch\":"), 3);
    }
}
