//! The node-side sovereign-group gate — W305 / R742-F1.
//!
//! A sovereign group is a **blast radius**: its own quorum, its own upgrade
//! cadence, its own destruction. Before this, the only thing standing between a
//! dev Pi and the prod quorum was a comment in three machine TOMLs saying
//! "never run a raft join against this box from a shell pointed at prod" —
//! habit, with no mechanism behind it. This module is the mechanism:
//! `POST /raft/add-learner` refuses a cross-group join instead of trusting the
//! shell the command was typed in.
//!
//! # The joiner is asked, never believed
//!
//! The whole scenario the gate exists for is *a command typed against the wrong
//! cluster*, so the joiner's group must come from the joiner. It is not read
//! from the request body and there is no CLI flag for it: the leader dials the
//! address it was given and reads what that node declares about itself
//! ([`ask_peer`]). Trusting the caller here would close nothing.
//!
//! # Unknown is not standalone
//!
//! `cloud::judge_join` reads two `MachineConfig`s, where a missing
//! `sovereign_group` genuinely means "standalone, in no group". A *daemon* has
//! a third state: started without `--sovereign-group`, or running a build that
//! predates the flag entirely. That is **unknown** — the declaration never
//! reached the box — and collapsing it into "standalone" would either lock
//! every un-rolled fleet out of growth or wave an unverifiable node into a
//! quorum. So [`PeerGroup`] is three-valued and [`judge`] resolves the unknown
//! before applying the shared predicate
//! ([`workload_spec::sovereign::join_permitted`], which both sides call so the
//! rule itself cannot drift).
//!
//! # The gate is in force exactly when the target declares a group
//!
//! If *this* node declares no group, it has asserted no blast radius, so there
//! is nothing to cross and the join is [`Gate::NotInForce`] — reported, never
//! silent. That is not a loophole: a pond cluster, a rig, and a BYO
//! single-node bootstrap legitimately have no group, and a gate that refused
//! them would break every deployment that has not been stamped and rolled.
//! It degrades toward the pre-R742-F1 behaviour and never below it, so the
//! guarantee is only fully in force once the group's nodes carry the flag —
//! the same shape R734-F5's region-spread clause settled on, for the same
//! reason.
//!
//! Once the target *does* declare a group, the gate is strict in the other
//! direction: an unknown joiner is refused, because "I could not establish
//! which blast radius that box belongs to" is not a reason to grow this one.
//!
//! # Membership is not eligibility (R605-F12)
//!
//! A group answers *which blast radius*; `--sovereign-role voter|non-voter`
//! answers *may it hold a seat*. Both sides of a join must be voters, so a box
//! that shares this cluster's fate without sharing its quorum — us-west-003,
//! a residential-uplink build worker that runs prod workloads — is refused by
//! its own declaration instead of by the absence of one.
//!
//! The role has a back-compat seam the group does not, because it shipped
//! later: a peer whose build predates it answers with no role key at all and is
//! read as a voter. That is deliberate and bounded; [`read_group`] carries the
//! reasoning and the window it leaves.

use std::time::Duration;

use serde::Deserialize;
use workload_spec::sovereign::{Membership, SovereignRole};

/// How long the leader waits for a joiner to answer "which group are you in?".
///
/// Short on purpose. This runs on the request path of an operator-driven verb,
/// and a node that cannot answer in a couple of seconds is not one to add to a
/// quorum — the leader is about to start replicating to it.
const ASK_TIMEOUT: Duration = Duration::from_secs(3);

/// What a peer said about its own sovereign group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerGroup {
    /// The peer declares this group (`yubaba serve --sovereign-group <label>`)
    /// and this role (`--sovereign-role`, R605-F12).
    ///
    /// A peer that answers with a group but no `sovereign_role` key at all —
    /// a build between R742-F1 and R605-F12 — arrives here as
    /// [`SovereignRole::Voter`], resolved in [`read_group`]. See there for why
    /// that is not [`Self::Unsupported`].
    Declared {
        group: String,
        role: SovereignRole,
    },
    /// The peer answered, and declares no group: it was started without
    /// `--sovereign-group`. The fix is a daemon restart with the flag, not a
    /// roll.
    Undeclared,
    /// The peer answered, but its build predates the field — it reports no
    /// `sovereign_group` key at all. Distinguished from [`Self::Undeclared`]
    /// because the operator's next action differs: roll that node, then set the
    /// flag. Both are refused; only the message changes.
    Unsupported,
}

/// What the gate decided about one proposed `add-learner`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// This node declares no sovereign group, so it is asserting no blast
    /// radius and the gate has nothing to judge. The join proceeds; the
    /// response says `sovereign_group_judged: false` so this is never mistaken
    /// for a check that passed.
    NotInForce,
    /// Both sides declare the same group and both are voters. Carries the group
    /// so the response can say which one was judged — the role is not carried
    /// because a permit implies `voter` on both sides.
    Permit(String),
    /// Refused, with an operator-readable reason. A refusal that only says
    /// "invalid" gets worked around rather than fixed, so every message here
    /// names what was seen on both sides and the exact edit that makes the join
    /// legal.
    Refuse(String),
}

/// Apply the gate. Pure — no I/O, so every branch is unit-testable without a
/// live cluster.
///
/// `target_group` / `target_role` are what *this* node (the leader receiving
/// the call) declares; `joiner` is what the prospective learner said when
/// asked. The two labels are how each node is named back to the operator — a
/// raft node id and address, at this layer, since a daemon does not know its
/// machine's `.yah/infra/machines` file name.
pub fn judge(
    target_group: Option<&str>,
    target_role: SovereignRole,
    target_label: &str,
    joiner: &PeerGroup,
    joiner_label: &str,
) -> Gate {
    let Some(target_group) = target_group else {
        return Gate::NotInForce;
    };

    // R605-F12: this node is a declared non-voter and is nonetheless serving
    // add-learner, which means it holds a raft seat its own declaration says it
    // must not. Refuse rather than grow the quorum from a box that is already
    // in a state the operator asked to be impossible.
    if !target_role.is_voter() {
        return Gate::Refuse(format!(
            "join refused: this cluster ({target_label}) declares itself a NON-VOTING member of \
             sovereign group {target_group:?} (--sovereign-role non-voter), so it should not be \
             holding a raft seat at all, let alone growing the quorum. Either this node was \
             started with a --raft-node-id it should not have, or the role is wrong — resolve \
             that before adding {joiner_label}."
        ));
    }

    match joiner {
        PeerGroup::Declared {
            group: joiner_group,
            role: joiner_role,
        } => {
            if workload_spec::sovereign::join_permitted(
                Membership::new(joiner_group, *joiner_role),
                Membership::new(target_group, target_role),
            ) {
                Gate::Permit(target_group.to_string())
            } else if joiner_group == target_group {
                // Same group, refused — so the role is the only thing it can
                // be, and printing the cross-group message here would name one
                // group twice and read as a bug in the check.
                Gate::Refuse(format!(
                    "join refused: the joiner {joiner_label} is a NON-VOTING member of sovereign \
                     group {target_group:?}, the same group as this cluster ({target_label}). It \
                     is inside this blast radius but declares itself ineligible for the quorum, \
                     so the join is refused by declaration rather than by omission. If it should \
                     genuinely vote, set `sovereign_role = \"voter\"` in its \
                     .yah/infra/machines/<name>.toml and restart its yubaba with \
                     --sovereign-role voter; if it should not, this refusal is the flag doing \
                     its job."
                ))
            } else {
                Gate::Refuse(format!(
                    "cross-group join refused: the joiner {joiner_label} is in sovereign group \
                     {joiner_group:?} and this cluster ({target_label}) is in \
                     {target_group:?}. These are separate blast radii — separate quorums, \
                     separate upgrade cadences, separately destroyable — and merging them is \
                     not something a join can undo. If the move is genuinely intended, restamp \
                     the joiner's `sovereign_group` to {target_group:?} in its \
                     .yah/infra/machines/<name>.toml, restart its yubaba with \
                     --sovereign-group {target_group}, and treat it as leaving its old group."
                ))
            }
        }
        PeerGroup::Undeclared => Gate::Refuse(format!(
            "join refused: this cluster ({target_label}) is in sovereign group \
             {target_group:?}, and the joiner {joiner_label} declares no sovereign group. That \
             is unknown, not standalone — nothing here can tell whether that box belongs to \
             another blast radius. Set `sovereign_group = {target_group:?}` in its \
             .yah/infra/machines/<name>.toml and restart its yubaba with --sovereign-group \
             {target_group}."
        )),
        PeerGroup::Unsupported => Gate::Refuse(format!(
            "join refused: this cluster ({target_label}) is in sovereign group \
             {target_group:?}, and the joiner {joiner_label} runs a yubaba that predates \
             sovereign groups — it reports no group at all, so there is nothing to check it \
             against. Roll that node first, then start it with --sovereign-group \
             {target_group}."
        )),
    }
}

/// The subset of `GET /raft/status` this gate reads.
///
/// A missing key and an explicit `null` must stay different — that is the
/// [`PeerGroup::Unsupported`] / [`PeerGroup::Undeclared`] split, and the two
/// get different operator instructions.
///
/// `#[serde(default)]` on a bare `Option<Option<_>>` does **not** give you
/// that, which is worth stating because it looks as though it should: serde
/// hands `null` straight to the outer `Option`, so both cases arrive as `None`
/// and an unflagged daemon gets told to roll a build it is already on. The
/// documented idiom is a `deserialize_with` that only runs when the key is
/// *present*, so absence falls through to `Default` and a present `null` is
/// `Some(None)`.
#[derive(Deserialize)]
struct PeerStatus {
    #[serde(default, deserialize_with = "present_but_maybe_null")]
    sovereign_group: Option<Option<String>>,
    /// R605-F12. Plain `#[serde(default)]` here, unlike the group above,
    /// because absence and `null` call for the *same* action: see
    /// [`read_group`].
    #[serde(default)]
    sovereign_role: Option<SovereignRole>,
}

/// Deserialize a present field into `Some(_)`, letting an absent one fall
/// through to [`Default`]. See [`PeerStatus`] for why this is not
/// `#[serde(default)]` alone.
fn present_but_maybe_null<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Ask the node at `addr` which sovereign group it declares.
///
/// `addr` is the raft membership address the `add-learner` call carried, and
/// `http://{addr}` is the same base URL the raft network client dials peers on
/// (`raft::network`), so no new address space is introduced.
///
/// `Err` means the question could not be put — unreachable, timed out, no raft
/// configured there, unparseable answer. That is reported as a transport
/// failure rather than folded into [`PeerGroup::Unsupported`], because "the box
/// did not answer" and "the box answered, with nothing" call for different
/// operator actions and a retry only helps for one of them.
pub async fn ask_peer(addr: &str) -> Result<PeerGroup, String> {
    let client = reqwest::Client::builder()
        .timeout(ASK_TIMEOUT)
        .build()
        .map_err(|e| format!("build http client: {e}"))?;
    let url = format!("http://{addr}/raft/status");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url}: {}", resp.status()));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| format!("GET {url}: reading body: {e}"))?;
    read_group(&body).map_err(|e| format!("GET {url}: {e}"))
}

/// Map a `/raft/status` body to what the peer declares.
///
/// Split out of [`ask_peer`] because the whole `Unsupported`/`Undeclared`
/// distinction rests on a serde subtlety — `Option<Option<_>>` under
/// `#[serde(default)]` — that is invisible at the call site and would fail
/// silently if it ever stopped holding, collapsing "old build" into "no group"
/// and giving the operator an instruction that cannot work.
///
/// # Why a missing `sovereign_role` is `Voter` and not a fourth peer state
///
/// R605-F12 added the role after the group, so there is a live population of
/// daemons — everything between R742-F1 and R605-F12, which today is the whole
/// prod raft — that answers with a group and no role key. Refusing those would
/// stop a stamped cluster from growing until every member had been rolled,
/// which is a strictly worse failure than the one the role guards against, and
/// it is the trade this module already made for the group itself: the gate
/// degrades toward the pre-R742-F1 behaviour and never below it.
///
/// The residue is a real window, worth naming rather than hiding: a box whose
/// `machine.toml` says `non-voter` but whose daemon predates `--sovereign-role`
/// answers "voter" and this gate lets it in. `cloud::judge_join` reads the TOML
/// and refuses it on the camp side, which is where operator-driven joins go —
/// so the window is a node-side backstop lagging a rollout, not an unguarded
/// path. It closes for a given group the moment its nodes carry the flag.
fn read_group(body: &str) -> Result<PeerGroup, String> {
    let status: PeerStatus =
        serde_json::from_str(body).map_err(|e| format!("unparseable /raft/status body: {e}"))?;
    Ok(match status.sovereign_group {
        Some(Some(group)) => PeerGroup::Declared {
            group,
            role: status.sovereign_role.unwrap_or_default(),
        },
        Some(None) => PeerGroup::Undeclared,
        None => PeerGroup::Unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOINER: &str = "node 11 at 100.64.0.11:7443";
    const TARGET: &str = "node 1 at 100.64.0.1:7443";

    /// A peer declaring `group` on a build that carries the role axis.
    fn declared(group: &str, role: SovereignRole) -> PeerGroup {
        PeerGroup::Declared {
            group: group.into(),
            role,
        }
    }

    /// This node is a voter in `target` — the ordinary case every test but the
    /// non-voting-target one wants.
    fn judge_against(target: Option<&str>, joiner: PeerGroup) -> Gate {
        judge(target, SovereignRole::Voter, TARGET, &joiner, JOINER)
    }

    #[test]
    fn a_join_within_one_group_is_permitted() {
        assert_eq!(
            judge_against(Some("prod"), declared("prod", SovereignRole::Voter)),
            Gate::Permit("prod".into())
        );
    }

    /// R605-F12: same group, still refused, and the message must say *role* —
    /// a cross-group message here would name "prod" twice and read as a bug.
    #[test]
    fn a_non_voting_joiner_is_refused_by_role_not_by_group() {
        let Gate::Refuse(msg) = judge_against(Some("prod"), declared("prod", SovereignRole::NonVoter))
        else {
            panic!("a non-voting member must not join its own group's quorum");
        };
        assert!(msg.contains("NON-VOTING"), "{msg}");
        assert!(msg.contains("--sovereign-role voter"), "{msg}");
        assert!(
            !msg.contains("cross-group"),
            "same-group refusal must not claim a cross-group cause: {msg}"
        );
    }

    /// The other end of the same assertion: a box declared non-voting is
    /// serving add-learner, so it holds a seat its own declaration forbids.
    /// Refuse before growing a quorum from it.
    #[test]
    fn a_non_voting_target_refuses_every_joiner() {
        for joiner in [
            declared("prod", SovereignRole::Voter),
            declared("prod", SovereignRole::NonVoter),
            declared("dev", SovereignRole::Voter),
        ] {
            let gate = judge(Some("prod"), SovereignRole::NonVoter, TARGET, &joiner, JOINER);
            let Gate::Refuse(msg) = gate else {
                panic!("a non-voting cluster must refuse joins, got {gate:?}");
            };
            assert!(msg.contains("--raft-node-id"), "{msg}");
        }
    }

    /// The case the gate exists for. It must name both groups: a refusal the
    /// operator has to go and reconstruct is one that gets worked around.
    #[test]
    fn a_cross_group_join_is_refused_naming_both_groups() {
        let Gate::Refuse(msg) = judge_against(Some("prod"), declared("dev", SovereignRole::Voter))
        else {
            panic!("a dev node joining prod must be refused");
        };
        assert!(msg.contains("dev") && msg.contains("prod"), "{msg}");
        assert!(msg.contains(JOINER) && msg.contains(TARGET), "{msg}");
    }

    /// An unstamped daemon is unknown, not standalone — and unknown does not
    /// grow a declared quorum.
    #[test]
    fn an_undeclared_joiner_is_refused_and_told_about_the_flag() {
        let Gate::Refuse(msg) = judge_against(Some("prod"), PeerGroup::Undeclared) else {
            panic!("an undeclared joiner must be refused");
        };
        assert!(msg.contains("--sovereign-group"), "{msg}");
    }

    /// A node whose build predates the field gets a different instruction —
    /// roll it first — because setting a flag its binary does not have would
    /// leave the operator repeating a fix that cannot work.
    #[test]
    fn an_old_build_is_refused_and_told_to_roll_first() {
        let Gate::Refuse(msg) = judge_against(Some("prod"), PeerGroup::Unsupported) else {
            panic!("a joiner that cannot report a group must be refused");
        };
        assert!(msg.contains("Roll that node"), "{msg}");
    }

    /// A cluster that declares nothing has asserted no blast radius, so there
    /// is nothing to cross. This is what keeps pond, rig and BYO single-node
    /// clusters — none of which are stamped — growable.
    #[test]
    fn an_unstamped_cluster_does_not_gate_at_all() {
        for joiner in [
            declared("dev", SovereignRole::Voter),
            declared("dev", SovereignRole::NonVoter),
            PeerGroup::Undeclared,
            PeerGroup::Unsupported,
        ] {
            assert_eq!(judge_against(None, joiner), Gate::NotInForce);
        }
    }

    /// The gate keys on the *declaration*, never on how the caller spelled the
    /// request — there is no request field it could read even if it wanted to.
    /// Exact comparison means a case typo is refused rather than silently
    /// treated as the real group.
    #[test]
    fn group_labels_are_compared_exactly() {
        assert!(matches!(
            judge_against(Some("dev"), declared("Dev", SovereignRole::Voter)),
            Gate::Refuse(_)
        ));
    }

    /// The serde subtlety the `Unsupported`/`Undeclared` split rests on: under
    /// `#[serde(default)]`, `Option<Option<_>>` reads a *missing* key as `None`
    /// and an explicit `null` as `Some(None)`. If that ever stopped holding it
    /// would fail silently — an old build would be told to set a flag its
    /// binary does not have, which is an instruction that can never work.
    #[test]
    fn a_missing_key_and_an_explicit_null_are_different_peers() {
        // A build that predates the field: it answers, with no such key.
        assert_eq!(
            read_group(r#"{"node_id":4,"state":"Learner"}"#).unwrap(),
            PeerGroup::Unsupported
        );
        // A current build started without --sovereign-group.
        assert_eq!(
            read_group(r#"{"node_id":4,"sovereign_group":null}"#).unwrap(),
            PeerGroup::Undeclared
        );
        assert_eq!(
            read_group(r#"{"node_id":4,"sovereign_group":"prod","sovereign_role":"voter"}"#)
                .unwrap(),
            declared("prod", SovereignRole::Voter)
        );
    }

    /// R605-F12's back-compat seam, pinned because it is a *decision* and not
    /// an oversight: a build that predates the role axis answers with a group
    /// and no role key, and is read as a voter so a stamped cluster stays
    /// growable mid-rollout. If this ever flips to a refusal, the whole prod
    /// raft stops accepting members until it has been rolled — see
    /// [`read_group`]'s doc for the window this leaves and why it is bounded.
    #[test]
    fn a_group_without_a_role_key_is_a_voter_not_a_refusal() {
        assert_eq!(
            read_group(r#"{"node_id":4,"sovereign_group":"prod"}"#).unwrap(),
            declared("prod", SovereignRole::Voter)
        );
        assert_eq!(
            read_group(r#"{"node_id":4,"sovereign_group":"prod","sovereign_role":null}"#).unwrap(),
            declared("prod", SovereignRole::Voter)
        );
    }

    /// The role travels in the same spelling the TOML and the CLI flag use, so
    /// a peer that declares itself non-voting is read as one.
    #[test]
    fn a_peer_reports_its_role_in_the_toml_spelling() {
        assert_eq!(
            read_group(r#"{"node_id":4,"sovereign_group":"prod","sovereign_role":"non-voter"}"#)
                .unwrap(),
            declared("prod", SovereignRole::NonVoter)
        );
    }

    /// Unrelated keys must not perturb the read — `/raft/status` grows sections
    /// (`members`, `liveness`) on its own schedule, and this gate reads one key
    /// out of it.
    #[test]
    fn unrelated_status_sections_are_ignored() {
        assert_eq!(
            read_group(
                r#"{"membership_config":{"x":1},"liveness":{"peers":{}},
                    "members":{"1":{"addr":"a","region":"us-west"}},
                    "sovereign_group":"dev","sovereign_role":"voter"}"#
            )
            .unwrap(),
            declared("dev", SovereignRole::Voter)
        );
    }

    #[test]
    fn a_body_that_is_not_json_is_an_error_not_an_undeclared_peer() {
        assert!(read_group("<html>502 Bad Gateway</html>").is_err());
    }
}
