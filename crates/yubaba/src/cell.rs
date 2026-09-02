//! A **cell** — one yubaba raft group bound to a jurisdiction — R736-T3 (W250).
//!
//! W250's design section says a cell is "one yubaba raft group (the W247
//! cluster) tagged with a region + jurisdiction", and that a tenant lives *in* a
//! cell: the global pointer at `tenants/<tenant>/cell.toml` names one
//! (`yah_tenant_pointer::PointerRecord::cell`), and the two-level fence
//! (R736-T2) lets a node act as owner of a tenant only while the pointer says
//! that tenant is in *this* node's cell. So a cell needs a name a node can
//! answer with, and until this module it had none.
//!
//! # The cell id is the sovereign group. There is no second label.
//!
//! The obvious implementation is a `--cell <id>` flag, and it would have been
//! wrong. R742-F1 already named "one yubaba raft group" for the fleet: the
//! [`sovereign_group`](crate::sovereign_group) — its own quorum, its own upgrade
//! cadence, separately destroyable, and already refusing cross-group joins on
//! `POST /raft/add-learner`. That is the same object W250 is describing, viewed
//! from the operational side instead of the residency side. A second label for
//! it would be two names for one thing, each settable independently, with
//! nothing making them agree — and the first disagreement is a tenant pointer
//! naming a "cell" that no raft group answers to.
//!
//! So: **a cell is a sovereign group that declares a jurisdiction.** The id in
//! the pointer record is the sovereign-group label. Everything the cross-cell
//! protocol needs from "these two raft groups must never merge" is R742-F1's
//! gate, already shipped and already tested — W250's *"never merge roaming into
//! the clean residency-bound cells"* rule is enforced by machinery that predates
//! this ticket, which is the point of not inventing a parallel one.
//!
//! Not every sovereign group is a cell. `dev` — three Pis with their own quorum
//! — is a blast radius with no residency meaning at all, and declaring it a
//! jurisdiction would be a lie a tenant could later be placed on. A group
//! becomes a cell exactly when an operator says which jurisdiction it is in.
//!
//! # Jurisdiction is declared per node, like the region — never per cluster
//!
//! `--jurisdiction` sits beside `--region` (R734-F5) and follows the same
//! protocol for the same reason: a node knows where *it* is and nothing about
//! anyone else, so each node declares its own and the cluster-level answer is
//! the agreement between them. Nothing here is replicated state — this is only
//! ever what this process was started with, and every *other* node's
//! jurisdiction is read off that node ([`crate::sovereign_group::ask_peer`]).
//!
//! That gives the enforcement point: [`judge`] runs on `add-learner` after the
//! blast-radius gate, so a box in the right group but the wrong jurisdiction —
//! the shape of a copy-pasted unit file, or a machine moved between DCs without
//! its TOML being updated — is refused rather than quietly widening a
//! residency-bound quorum across a legal boundary.
//!
//! # Region: already carried, deliberately not re-declared here
//!
//! The ticket asks for region *and* jurisdiction on a raft group. Region is
//! R734-F2/F5's and is already live: each node declares `--region` and publishes
//! it into its own [`MemberInfo`](crate::raft::MemberInfo) row, and
//! `QuorumGeography::MustSpanRegions` already forbids one region holding a
//! majority of a cell's voters. A cell-level region tag would be a *third*
//! spelling of a fact two already answer, and it could not be a single label
//! anyway: a residency-bound cell spans several regions on purpose (a US cell as
//! `us-west` / `us-east` / `us-south`, 1-1-1) precisely so that losing one does
//! not stop writes. So the cell's regions are **derived** — [`describe`] reports
//! the distinct regions its member rows declare — rather than declared a second
//! time and left to drift.
//!
//! # Label constraints are the pointer's, not ours
//!
//! A cell id is written into the global pointer object as
//! `PointerRecord::cell`, and `yah_tenant_pointer`'s `check_identifier` refuses
//! an empty label, one containing `/`, and one containing whitespace or a
//! control character. A cell whose id that crate would refuse cannot be moved
//! into or out of — the failure would land in the middle of a move protocol,
//! months later, on a value fixed at boot. [`check_label`] applies the same rule
//! at startup instead, where the fix is a flag edit.
//!
//! yubaba does **not** link `yah-tenant-pointer` to share that function: the
//! crate is `publish = false` and holds no crates.io name, and yubaba is
//! published, so taking the dependency would force a publishing decision on
//! another relay's crate to share nine lines of validation. The rule is
//! duplicated deliberately and named on both sides;
//! [`tests::the_pointer_crates_identifier_rule_is_the_one_applied_here`] pins the
//! exact character classes so a drift is a test failure rather than a runtime
//! surprise.

use std::collections::BTreeSet;

/// The cell this node is in: a sovereign-group id plus the jurisdiction that
/// makes it residency-meaningful.
///
/// Derived, never stored — see [`identify`]. Two fields that can be set
/// independently are two fields that can disagree, and the whole argument in the
/// module docs is that they must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellIdentity {
    /// The sovereign-group label, which is also the cell id written into
    /// `yah_tenant_pointer::PointerRecord::cell`.
    pub id: String,
    /// The legal jurisdiction this cell's data is bound to, e.g. `"us"` /
    /// `"eu"`. The label space R733-F1's `home_jurisdiction` will compare
    /// against — one taxonomy, the same shape `MemberInfo::region` shares with
    /// `MachineConfig::region`.
    pub jurisdiction: String,
}

/// What this node's two flags say about which cell it is in.
///
/// `Ok(None)` is the ordinary answer for most of the fleet today: a group with
/// no jurisdiction is a blast radius that is not a cell, and a node with neither
/// flag is a pond/rig/BYO node that is neither.
///
/// The one refusal is a jurisdiction with no group. It is not merely useless —
/// it is a residency claim with no cell id to attach to, so nothing downstream
/// can act on it and an operator reading `--jurisdiction eu` on the unit file
/// would reasonably believe a boundary was being enforced. Failing at startup
/// costs a flag edit; accepting it costs the belief.
pub fn identify(
    sovereign_group: Option<&str>,
    jurisdiction: Option<&str>,
) -> Result<Option<CellIdentity>, String> {
    match (sovereign_group, jurisdiction) {
        (_, None) => Ok(None),
        (None, Some(jurisdiction)) => Err(format!(
            "--jurisdiction {jurisdiction:?} was given without --sovereign-group. A jurisdiction \
             names a CELL, and a cell is one raft group: the sovereign-group label is the cell id \
             the global tenant pointer records (tenants/<tenant>/cell.toml), so a jurisdiction \
             with no group has nothing to name. Pass --sovereign-group <label> as well (copy the \
             `sovereign_group` this machine declares in .yah/infra/machines/<name>.toml), or drop \
             --jurisdiction if this cluster is not a residency cell."
        )),
        (Some(group), Some(jurisdiction)) => {
            check_label("cell id (--sovereign-group)", group)?;
            check_label("jurisdiction (--jurisdiction)", jurisdiction)?;
            Ok(Some(CellIdentity {
                id: group.to_string(),
                jurisdiction: jurisdiction.to_string(),
            }))
        }
    }
}

/// Refuse a label the global tenant pointer could not carry.
///
/// Mirrors `yah_tenant_pointer::check_identifier` — see the module docs for why
/// the rule is duplicated rather than imported.
pub fn check_label(what: &str, value: &str) -> Result<(), String> {
    let refuse = |why: &str| {
        Err(format!(
            "{what} {value:?} is not a usable label: {why}. It is written into the global tenant \
             pointer as the cell id, and yah_tenant_pointer refuses identifiers of this shape, so \
             a cluster carrying it could never be moved into or out of."
        ))
    };
    if value.is_empty() {
        return refuse("it is empty");
    }
    if value.contains('/') {
        return refuse("it contains '/', which would re-shape the object key");
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return refuse("it contains whitespace or a control character");
    }
    Ok(())
}

/// What a peer said about its own jurisdiction, read off its `/raft/status`.
///
/// Three-valued for the same reason [`PeerGroup`](crate::sovereign_group::PeerGroup)
/// is: a missing key and an explicit `null` are different facts with different
/// operator actions, and collapsing them tells someone to roll a build they are
/// already on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerJurisdiction {
    /// The peer declares this jurisdiction (`yubaba serve --jurisdiction`).
    Declared(String),
    /// The peer answered and declares none: it was started without the flag.
    /// The fix is a restart, not a roll.
    Undeclared,
    /// The peer answered, but its build predates the field — no `jurisdiction`
    /// key at all. Roll it first, then set the flag.
    Unsupported,
}

/// What the cell gate decided about one proposed `add-learner`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// This node is in no cell (no jurisdiction declared), so it is asserting no
    /// residency boundary and there is nothing to cross. Reported in the
    /// response as `cell_judged: false`, never silent.
    NotInForce,
    /// Both sides are in the same jurisdiction. Carries it so the response can
    /// say which one was judged.
    Permit(String),
    /// Refused, naming what was seen on both sides and the exact edit that makes
    /// the join legal.
    Refuse(String),
}

/// Apply the cell gate. Pure — no I/O, so every branch is unit-testable.
///
/// Runs *after* [`sovereign_group::judge`](crate::sovereign_group::judge) on the
/// `add-learner` path: the blast-radius question ("is this box even in my raft
/// group?") is the coarser one, and answering residency first would produce a
/// refusal about jurisdictions for a node that was never joining this cluster in
/// the first place.
///
/// It follows that a permit here is always *within* one sovereign group. A
/// jurisdiction mismatch at that point is not two cells meeting — it is one cell
/// disagreeing with itself, which is a misconfiguration on one of the two boxes
/// rather than an operator reaching for the wrong cluster.
pub fn judge(
    target_jurisdiction: Option<&str>,
    target_label: &str,
    joiner: &PeerJurisdiction,
    joiner_label: &str,
) -> Gate {
    let Some(mine) = target_jurisdiction else {
        return Gate::NotInForce;
    };

    match joiner {
        PeerJurisdiction::Declared(theirs) if theirs == mine => Gate::Permit(mine.to_string()),
        PeerJurisdiction::Declared(theirs) => Gate::Refuse(format!(
            "cross-jurisdiction join refused: this cell ({target_label}) is bound to jurisdiction \
             {mine:?} and the joiner {joiner_label} declares {theirs:?}. A cell is one raft group \
             in one jurisdiction — every tenant the global pointer places here is placed on the \
             promise that its data does not leave {mine:?}, and a voter in {theirs:?} breaks that \
             promise for every tenant in the cell at once, not just for new ones. Since both boxes \
             agree on the sovereign group, one of the two `jurisdiction` values is simply wrong: \
             fix it in that machine's .yah/infra/machines/<name>.toml, restart its yubaba with the \
             corrected --jurisdiction, and retry. If the box really is in {theirs:?}, it belongs to \
             the {theirs:?} cell and must join that one instead — moving a TENANT between cells is \
             the cross-cell move protocol (W250 §5), never a raft join."
        )),
        PeerJurisdiction::Undeclared => Gate::Refuse(format!(
            "join refused: this cell ({target_label}) is bound to jurisdiction {mine:?}, and the \
             joiner {joiner_label} declares no jurisdiction. That is unknown, not \
             jurisdiction-free — nothing here can tell which legal boundary that box sits inside. \
             Set `jurisdiction = {mine:?}` in its .yah/infra/machines/<name>.toml and restart its \
             yubaba with --jurisdiction {mine}."
        )),
        PeerJurisdiction::Unsupported => Gate::Refuse(format!(
            "join refused: this cell ({target_label}) is bound to jurisdiction {mine:?}, and the \
             joiner {joiner_label} runs a yubaba that predates cell tagging — it reports no \
             jurisdiction at all, so there is nothing to check it against. Roll that node first, \
             then start it with --jurisdiction {mine}."
        )),
    }
}

/// The `cell` section of `GET /raft/status`.
///
/// `regions` is derived from the replicated member rows rather than declared:
/// see the module docs. It is what the cell's nodes *say about themselves*, so
/// it is empty on a cluster whose members have not registered yet and grows as
/// they do — the same lag `members` itself carries, and for the same reason.
pub fn describe(identity: &CellIdentity, regions: BTreeSet<String>) -> serde_json::Value {
    serde_json::json!({
        "id": identity.id,
        "jurisdiction": identity.jurisdiction,
        "regions": regions.into_iter().collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_without_a_jurisdiction_is_a_blast_radius_but_not_a_cell() {
        assert_eq!(
            identify(Some("dev"), None),
            Ok(None),
            "the dev raft group has its own quorum and no residency meaning; declaring it a cell \
             would let a Locked tenant be placed on it"
        );
        assert_eq!(identify(None, None), Ok(None));
    }

    #[test]
    fn a_jurisdiction_without_a_group_is_refused_because_it_names_no_cell() {
        let err = identify(None, Some("eu")).expect_err("must refuse");
        assert!(
            err.contains("--sovereign-group") && err.contains("cell id"),
            "the refusal must name the missing flag and why the two are one label: {err}"
        );
    }

    #[test]
    fn a_group_and_a_jurisdiction_make_a_cell_whose_id_is_the_group() {
        assert_eq!(
            identify(Some("prod-us"), Some("us")),
            Ok(Some(CellIdentity {
                id: "prod-us".to_string(),
                jurisdiction: "us".to_string(),
            })),
            "the cell id must BE the sovereign-group label, not a second one derived from it"
        );
    }

    /// The rule `yah_tenant_pointer::check_identifier` applies to a `cell`
    /// value, restated here because yubaba deliberately does not link that crate
    /// (module docs). If this test and that function ever disagree, the symptom
    /// is a cluster that boots and then cannot be moved.
    #[test]
    fn the_pointer_crates_identifier_rule_is_the_one_applied_here() {
        for bad in ["", "us/west", "us west", "us\nwest", "us\tw", "us\u{0}w"] {
            assert!(
                check_label("cell id", bad).is_err(),
                "yah_tenant_pointer would refuse {bad:?} as a cell id, so this must too"
            );
        }
        for good in ["prod-us", "prod_eu", "cell.1", "US"] {
            assert!(
                check_label("cell id", good).is_ok(),
                "{good:?} is a legal pointer identifier and must be accepted"
            );
        }
    }

    #[test]
    fn a_bad_label_is_caught_at_identify_time_on_either_flag() {
        assert!(
            identify(Some("prod/us"), Some("us")).is_err(),
            "a group label the pointer would refuse must fail at startup, not at move time"
        );
        assert!(
            identify(Some("prod-us"), Some("e u")).is_err(),
            "the jurisdiction label is bound for R733-T3's bucket naming; hold it to the same rule"
        );
    }

    #[test]
    fn a_node_in_no_cell_judges_nothing() {
        assert_eq!(
            judge(
                None,
                "node 1",
                &PeerJurisdiction::Declared("eu".into()),
                "node 2"
            ),
            Gate::NotInForce,
            "a cluster asserting no residency boundary has nothing to cross"
        );
    }

    #[test]
    fn same_jurisdiction_permits_and_names_it() {
        assert_eq!(
            judge(
                Some("us"),
                "node 1",
                &PeerJurisdiction::Declared("us".into()),
                "node 2"
            ),
            Gate::Permit("us".to_string())
        );
    }

    /// The message has to be actionable without the reader knowing this code:
    /// both values, which file to edit, and the fact that a raft join is not how
    /// a tenant changes cell.
    #[test]
    fn a_mismatch_names_both_jurisdictions_and_the_move_protocol() {
        let Gate::Refuse(reason) = judge(
            Some("us"),
            "node 1",
            &PeerJurisdiction::Declared("eu".into()),
            "node 2 at 127.0.0.1:9",
        ) else {
            panic!("a cross-jurisdiction join must be refused");
        };
        assert!(
            reason.contains("\"us\"") && reason.contains("\"eu\""),
            "name both sides: {reason}"
        );
        assert!(
            reason.contains("node 2 at 127.0.0.1:9"),
            "name the joiner the operator typed: {reason}"
        );
        assert!(
            reason.contains("machines/<name>.toml"),
            "name the file to edit: {reason}"
        );
        assert!(
            reason.contains("move protocol"),
            "an operator whose real intent is moving a tenant must be told the right verb: \
             {reason}"
        );
    }

    /// Undeclared and Unsupported are both refusals, and the whole point of
    /// keeping them apart is that the instruction differs.
    #[test]
    fn an_unflagged_joiner_is_told_to_restart_and_an_old_build_to_roll() {
        let Gate::Refuse(undeclared) =
            judge(Some("us"), "node 1", &PeerJurisdiction::Undeclared, "node 2")
        else {
            panic!("an undeclared joiner must be refused");
        };
        assert!(
            undeclared.contains("--jurisdiction us") && !undeclared.contains("Roll that node"),
            "an unflagged node needs a restart with the flag, not a roll: {undeclared}"
        );

        let Gate::Refuse(unsupported) = judge(
            Some("us"),
            "node 1",
            &PeerJurisdiction::Unsupported,
            "node 2",
        ) else {
            panic!("an old build must be refused");
        };
        assert!(
            unsupported.contains("Roll that node"),
            "a build with no jurisdiction field cannot be fixed by a flag: {unsupported}"
        );
    }

    #[test]
    fn describe_reports_the_derived_regions_of_the_cell() {
        let identity = CellIdentity {
            id: "prod-us".into(),
            jurisdiction: "us".into(),
        };
        let regions: BTreeSet<String> = ["us-west", "us-east", "us-west"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            describe(&identity, regions),
            serde_json::json!({
                "id": "prod-us",
                "jurisdiction": "us",
                "regions": ["us-east", "us-west"],
            }),
            "regions are the distinct labels the member rows declare, sorted and de-duplicated"
        );
    }

    #[test]
    fn a_cell_with_no_registered_members_yet_reports_no_regions() {
        let identity = CellIdentity {
            id: "prod-eu".into(),
            jurisdiction: "eu".into(),
        };
        assert_eq!(
            describe(&identity, BTreeSet::new())["regions"],
            serde_json::json!([]),
            "an empty member map is a lag, not an error — the cell is still a cell"
        );
    }
}
