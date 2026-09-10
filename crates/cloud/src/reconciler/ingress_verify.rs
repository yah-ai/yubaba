//! Is the backend reachable at the port its service record advertises? — the
//! half [`collate_workspace_ingress`](crate::validate::collate_workspace_ingress)
//! deliberately cannot answer (R844-F16).
//!
//! **Read [§What this does not prove](#what-this-does-not-prove) before
//! treating a green result as a deploy gate.** That question is narrower than
//! "does the front door work", and on 2026-09-03 the difference took yah.dev
//! down for four minutes.
//!
//! `yah cloud ingress collate` is pure: no network, no credentials. That purity
//! is load-bearing — it is what lets `xtask/tests/mirror_ingress.rs` plan this
//! camp's real `.yah/services/` tree as a unit test — but it means the
//! `100.64.0.3:8080` it prints is an **echo of declarations**: the mirror's
//! `upstream_host` pin, or since R844-F12 the placement machine's declared
//! `[registration].mesh_ipv4`. Collate attests that the mirrors *cohere*. It
//! has never attested that anything answers.
//!
//! That distinction is not academic in this repo. The apex's `upstream_host`
//! was once left at `127.0.0.1` after a second front door existed, and collate
//! rendered it exactly as confidently as it renders a correct one — for the
//! nineteen days the site was frozen.
//!
//! ## Four claims, and this module measures only the third
//!
//! | claim | evidence | who says it |
//! |---|---|---|
//! | "the mirrors agree on what fronts what" | the declaration tree | `collate` |
//! | "a ready record exists for it" | `GET /service-records?ready=true` | [`ServiceRecordFanout`] |
//! | "that record's address answers" | a TCP connect | **this module** |
//! | "the front door is configured to dial it" | an HTTPS GET of the hostname, compared against the backend | **this module**, [`apply_public_path`] (R844-F18) |
//!
//! The second is *yubaba's opinion*, and R844-B11 is the proof it can be wrong
//! while looking right: us-west-001 advertised `100.64.0.3:4325` as `Ready`
//! while the workload answered on `100.64.0.1:4325`. The record was healthy,
//! the record's own address refused connections, and every layer above it
//! reported success. A connect is the only step that can catch that, because it
//! is the only step that asks the world instead of asking a declaration.
//!
//! ## What this does not prove
//!
//! **Updated by R844-F18 — the gap this section describes is now closed by
//! [`apply_public_path`], and the history below is why that check exists and
//! what it is still not.** [`verify_collation`] alone proves **the backend is
//! reachable at the port the record advertises**; on its own it never proves
//! **the front door is configured to dial that port**. Those two coincide only
//! while a pin forces them to — so that pass is *weakest in exactly the
//! portless configuration it was built to certify*.
//!
//! That is not a theoretical gap. R844-T10 deleted the apex's `port` pin on the
//! strength of a green run from this verb, on 2026-09-03:
//!
//! * kamaji allocated a **new** port for the redeployed workload — 34759;
//! * the service record correctly advertised 34759;
//! * this verb dialed 34759, found it open, and printed
//!   *"2 rule(s) … 2 proven to serve, 0 not"*;
//! * the public got **HTTP 503** for four minutes, because the running passway
//!   was still configured for 8080 and **nothing reconfigures it**.
//!
//! So the verb reported success during the live outage it was built to prevent.
//! The prior measurement that authorised the edit was green for a reason that
//! did not survive a real deploy: it stripped the pins from a *copy* of the
//! config while the old workload was still bound to 8080, which is the one
//! arrangement in which the record and the front door cannot disagree.
//!
//! This is [`collate`]'s own limitation one level up — collate attests
//! coherence and not reachability; a dial attests reachability of a *record*,
//! and not that the front door agrees with that record.
//!
//! [`apply_public_path`] closes it by traversing the **public path** and
//! comparing: it fetches the publish beacon
//! ([`publish_beacon`](crate::reconciler::publish_beacon)) from
//! `https://<hostname>/` and from each discovered backend, and fails the rule
//! when the two serve different publishes. A bare `GET /` would not have done —
//! a door pointed at the wrong backend answers 200 with a plausible page, which
//! is how the apex stayed frozen for nineteen days. The beacon is the only
//! object on either side that says *which publish this is*.
//!
//! **Two things that check is still not.** It is a **detector of the current
//! state**, not a simulation of a pending edit — run it before and after an
//! apply and require both green. And the public fetch goes wherever **DNS**
//! sends it, so a hostname on two front doors is measured at one of them; the
//! verdict says so in a note rather than implying it covered both.
//!
//! **So: a green [`verify_collation`] alone is necessary, not sufficient. Do
//! not use it without the public-path pass as the gate on removing a pin.**
//!
//! [`collate`]: crate::validate::collate_workspace_ingress
//!
//! ## Why this is a separate verb and not a flag on `collate`
//!
//! Because the purity above is the feature. A `--live` flag would put a network
//! read inside the function eleven offline tests call, and the pressure to make
//! those tests pass would then push the network read towards being optional in
//! a way that silently degrades. A sibling verb costs nothing that flag would
//! not cost more.
//!
//! ## Pure, like everything else on this seam
//!
//! Nothing here opens a socket. The caller does the fanout read and the dial,
//! and hands both in as data — the fifth instance of the shape
//! [`resolve_ingress_placements`](crate::reconciler::resolve_ingress_placements),
//! [`IngressPlan::resolve_upstreams`], [`IngressPlan::resolve_ports`] and
//! [`IngressPlan::resolve_upstreams_from_config`] already use. So the verdict
//! logic — which is where the interesting mistakes live — is unit-testable
//! against a fake fleet with no network at all.
//!
//! ## A subset renders like a success, so a subset is a failure
//!
//! The failure class this whole relay exists to remove is a partial answer that
//! looks complete. A rule placed on two nodes that resolves one address is
//! *half a front door*: it renders, it dials, it serves — and half the fleet's
//! traffic capacity is silently absent. [`RuleVerdict`] therefore fails a rule
//! whose resolved backends do not cover its whole declared placement, and names
//! the node that went missing along with why.
//!
//! @yah:ticket(R844-F18, "Verify the PUBLIC path — an HTTPS GET of the hostname through the real front door, compared against what the record claims")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-09-04T01:55:44Z)
//! @yah:parent(R844)
//! @yah:next("KEEP `collate` PURE (R772, R844-F5, R844-F12, R844-F16 each fought for this) and prefer a third verb or a flag on `verify` over touching it. `cargo test -p xtask --test main mirror_ingress` planning the camp's REAL .yah/services tree with no network is the property being protected; it is currently 11 green.")
//! @yah:verify("And it must still be green on the healthy fleet: https://yah.dev/ through both declared front doors, agreeing with what `yah cloud ingress verify` resolves.")
//! @yah:gotcha("A LIVE-OUTAGE-DETECTOR IS NOT AUTOMATICALLY A PRE-FLIGHT GATE, and this ticket should be honest about which it is building. An HTTPS GET proves the CURRENT front door serves; it cannot tell you what a config change is ABOUT to do, because the front door has not been reconfigured yet. That may still be enough — run it before and after an apply and require both green — but say so explicitly rather than letting a future reader assume it gates the edit. The failure that started this was precisely someone (twice) treating a green from the wrong vantage point as authorisation.")
//! @yah:next("A SHAPE FOR THIS, from @Ashguard:griffin (session:75f87e36, the session that caused the outage behind it) — offered as a starting point, not a settled design. The open question on this ticket is whether an HTTPS GET is a pre-flight GATE or only an outage DETECTOR. I think it is only ever a detector, and that the ticket is really TWO checks answering two different questions:\n\n  1. PRE-FLIGHT, and it is not a probe at all — it is a COMPARISON. Read what the front door is actually configured to dial, FROM THE DOOR, and compare it against what the service record says the backend is. That is the check that would have caught tonight's outage BEFORE it happened, because the two disagreed (passway held 8080, the record advertised 34759) at a moment when every probe of either side in isolation was green. Note what makes it different from R844-F16's verify: verify reads the record and dials the port the record names, so both of its inputs come from the same side of the disagreement. The door's own configured value is the input nobody currently reads, and it is the only one that makes the comparison possible.\n\n  2. POST-CONDITION, which is where the HTTPS GET belongs — an unauthenticated GET of the public hostname through the real front door, asserted AFTER an apply, once R844-B19 guarantees the door has actually been repointed. Today that assertion cannot be trusted to mean anything, because B19's ordering bug means the door may never have been updated at all; the GET would just be re-measuring the old configuration and calling it a pass.\n\nWHY THIS PAIRS F18 WITH B19 RATHER THAN DUPLICATING IT: B19 makes the front-door update reliably HAPPEN; (2) is the assertion that it DID; (1) is the only one of the three that can speak before a change is applied. Sequencing follows from that — do not land (2) before B19, or it encodes today's broken ordering as the expected one.\n\nTHE CAVEAT I CANNOT RESOLVE AND WHOEVER TAKES THIS SHOULD NOT ASSUME AWAY: even (1) compares two CURRENT states. It does not simulate what a config change is about to do, which is what we actually wanted to know tonight. It catches an existing divergence, and it would catch this specific class because the divergence appears the moment the workload is redeployed — but it is not a general \"is this edit safe\" oracle, and nothing in this design is. If someone needs that, it is a different and much larger ticket, and it should be filed as one rather than smuggled in here.")
//! @yah:handoff("LANDED. `yah cloud ingress verify` now takes the fourth step, on by default. For every hostname in the collation it fetches `https://&lt;hostname&gt;/.well-known/yah-publish.json`, for every discovered backend it fetches the same object over the mesh, and it FAILS the rule when the two name different publishes. Verdict logic is `apply_public_path` in oss/yubaba/crates/cloud/src/reconciler/ingress_verify.rs, pure like the rest of that seam — the CLI does both fetches and hands them in as `PublicReadings`, so the interesting mistakes are unit-testable against a fake fleet. New surface: `BeaconFetch`, `PublicReadings`, `apply_public_path`, three `VerifyFinding` arms, `fetch_beacon` and `--skip-public` in app/yah/cli/src/cloud.rs.")
//! @yah:handoff("THE COMPARISON IS THE CONTENT, NOT THE GET — this is the design decision, and the ticket title's \\\"HTTPS GET\\\" understates it. A bare `GET /` proves only that something answered: a door pointed at the wrong backend returns 200 with a plausible page, which is exactly how the apex stayed frozen for nineteen days with every signal green. The publish beacon (`publish_beacon.rs`, `BEACON_KEY = .well-known/yah-publish.json`, R703-B4) is the one object on either side of the door that says WHICH PUBLISH THIS IS, so fetching it from both and comparing digests is what turns \\\"something answered\\\" into \\\"the front door is serving the backend the records name\\\". Reused rather than invented — the object already exists, `mesofact serve` already answers it out of the bundle, and R2 static publishes already write it.")
//! @yah:handoff("THE TICKET'S OWN OPEN QUESTION — GATE OR DETECTOR — ANSWERED, AND ANSWERED THE WAY ITS FILER EXPECTED: **detector**, and the code says so in its own output rather than leaving a reader to infer it. `apply_public_path`'s doc, the CLI `--help`, the summary line printed on every run, W267 and the service-toml guide all now carry the same sentence: it compares two CURRENT states, cannot simulate an edit you have not applied, and the protocol is run-before-and-after-and-require-both-green. That is enough for the failure it was built for — the divergence appears the moment the workload is redeployed onto a new port — and it is deliberately NOT sold as an \\\"is this edit safe\\\" oracle. @Ashguard:griffin's caveat on this ticket was right and is preserved as the design, not assumed away.")
//! @yah:handoff("GRIFFIN'S PART (1), THE PRE-FLIGHT \\\"READ THE DOOR'S OWN CONFIG AND COMPARE\\\", IS NOT WHAT SHIPPED — say so plainly rather than letting the ticket read as fully covered. Their shape proposed reading what passway is CONFIGURED to dial, from the door, and comparing that against the record. This ships the equivalent comparison one layer out: what the door ACTUALLY SERVES versus what the backend serves. Why that substitution rather than the config read: the running passway holds its upstreams in container env (`PASSWAY_UPSTREAMS`, `PASSWAY_UPSTREAM_SOURCE=static` — oss/passway/crates/passway/src/main.rs), so reading it means an SSH or a docker inspect per door, i.e. credentials and a shell on a production box inside a read-only verb. The served comparison needs neither, catches the same divergence class (it is true exactly when the door is dialing something else), and additionally catches a stale edge cache, which a config read cannot see. What the config read would still buy is naming WHY they diverge; that is a genuinely separable ticket and is not smuggled in here.")
//! @yah:handoff("A FAILURE IS ONLY A FAILURE WHEN SOMETHING WAS ACTUALLY COMPARED — the design care, and the thing a careless version of this gets wrong in the direction that matters. Three arms produce a NOTE and leave the rule clean rather than a finding: a hostname that answers 200 with no beacon (it fronts something that is not a mesofact publish — a limit on the check, not a fault of the host, and failing it would red every non-bundle hostname in the fleet); a public 200 with no comparable backend (the note says verbatim that this proves the hostname is up and NOT that it is fronting the discovered backend); and a hostname nobody measured. Two arms fail: a transport failure, and a non-2xx. One arm is the point: `PublicBackendDivergence`, which names both digests and the backend address it compared against. And a backend that answers without a beacon adds nothing — `verify_collation` already dialed it and said what it found, so a second opinion phrased as an error would double-count one fact.")
//! @yah:gotcha("THE LIMIT I COULD NOT DESIGN AWAY, AND DID NOT HIDE: the public fetch goes wherever DNS sends it, so a hostname published through two front doors is measured at ONE of them and this pass cannot say which. A divergence affecting only the other door reads as clean. Every verdict for such a hostname carries a note saying so — but only once a comparison actually happened, since on a rule where nothing could be compared that note is noise stacked on the finding. Closing it needs a fetch pinned to each door's public address with a `Host` override, which needs a public IP per door that nothing in the `Collation` carries today. Pinned by `a_hostname_on_two_front_doors_is_noted_as_measured_at_only_one`.")
//! @yah:verify("UNIT: `cargo test --manifest-path oss/yubaba/Cargo.toml -p yah-cloud --lib ingress_verify` = 19 passed / 0 failed (11 before, +8 new). THE ONE THAT MATTERS IS `a_503_at_the_apex_fails_a_rule_whose_mesh_side_is_entirely_green` — it reproduces the 2026-09-03 outage as a unit test, asserting FIRST that `verify_collation` alone reports the rule clean (that assertion is the precondition, because a green mesh side is what reported success during the outage) and THEN that the public leg fails it. The other seven cover the stale-serve shape (200 serving a different digest than the backend), a transport failure, a hostname with no beacon, a public 200 with nothing to compare, an unmeasured hostname, a hostname on two doors, and the fully-clean case where the two digests match and NOTHING is caveated. Wider: `-p yah-cloud --lib ingress` = 94 passed / 0 failed; `-p yah-cloud --lib` = 1019 passed / 0 failed / 4 ignored (1011 before, so +8 and nothing lost).")
//! @yah:verify("THE PURITY CANARY, which this ticket's own `next` named as the property to protect: `cargo test -p xtask --test main mirror_ingress` = 11 passed / 0 failed. `collate` was not touched — the public leg is a fourth step on `verify`, per the same reasoning R844-F16 used to make `verify` a sibling verb rather than a flag. `cargo check --workspace --all-targets` cargo-exit=0, zero `^error` lines. Installed and re-installed with `cargo xtask install` (sha256 b751f470e329253765075e5c050256f4e848ae1e9265f55fd6965f024bafbf24, `PATH resolves here`), per this relay's standing gotcha that `cargo build` does not update the binary an operator runs.")
//! @yah:verify("THIS TICKET'S STATED ACCEPTANCE TEST — \\\"green on the healthy fleet, https://yah.dev/ through both declared front doors, agreeing with what verify resolves\\\" — WAS **NOT** MET, AND NOT BECAUSE OF THIS CHANGE. The fleet is not healthy right now: the mesh coordination server is down (`cloud.mesh.yah.dev` -&gt; 15.204.89.240 REFUSES :443 and :80 while :22 answers, and `tailscale status` reports this machine logged out with \\\"fetch control key ... connection refused\\\"), so NO 100.64.0.0/10 address is reachable from here and the mesh half of the check cannot run at all. Filed as R858 with the full measurement chain. I am recording this as unmet rather than reporting a partial green.")
//! @yah:verify("WHAT THE LIVE RUN DID PROVE, and it is more than nothing: `yah cloud ingress verify --path .` from the freshly installed binary fetched `https://yah.dev/.well-known/yah-publish.json` over the real public internet, parsed it, and — because no backend beacon could be read across the dead mesh — printed exactly the right sentence instead of a pass: \\\"https://yah.dev answers with a publish beacon, but no discovered backend served one to compare it against, so this proves the hostname is up and NOT that it is fronting the discovered backend\\\". Independently confirmed by hand: `curl https://yah.dev/` = HTTP 200 in 0.81s and the beacon is `{\\\"prefix\\\":\\\"bundle/yah-marketing\\\",\\\"digest\\\":\\\"bfb47cd42468b080c474193fa6091ec273b6c99ab5a8a3b91d9c847cd7278551\\\",\\\"files\\\":39}`. So the public leg ran end to end against production and, on a real unplanned failure it was never designed for, refused to overclaim — which is the behaviour this ticket exists to install. `--skip-public` also exercised live: every verdict then reads \\\"the public path was not checked for yah.dev — this verdict speaks only for the mesh side, which is necessary and not sufficient\\\", and the summary names the dropped claim.")
//! @yah:next("RE-RUN THE ACCEPTANCE TEST ONCE R858 CLEARS — it is one command and it is the only thing outstanding on this ticket: `yah cloud ingress verify --path .` must exit 0 with both front doors' rules reporting the mesh dial open AND the public beacon matching the backend's. Until the mesh is reachable that run measures nothing about the fourth claim.")
//! @yah:notify_on(R858, "The mesh is reachable again — run this ticket's outstanding acceptance test: `yah cloud ingress verify --path .` must exit 0 with BOTH front doors reporting the mesh dial open AND the public beacon digest matching the backend's. It could not be run at landing time because no 100.64.0.0/10 address answered. If it passes, that closes the last open item here; if it fails, read which of the two legs failed before touching the code — the mesh leg is R844-F16's and predates this change.")

use std::collections::BTreeMap;
use std::fmt;

use crate::reconciler::ingress::{Collation, IngressPlan, IngressRule};
use crate::reconciler::service_discovery::ServiceRecordFanout;

/// What a TCP connect to one resolved `host:port` actually did.
///
/// Two arms, no `Unknown`: unlike a discovery read — which can fail to *ask* a
/// node, and whose whole vocabulary
/// ([`RecordVisibility`](crate::reconciler::RecordVisibility)) exists to keep
/// that apart from an empty answer — a dial either completed or it did not.
/// The attempt is the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialOutcome {
    /// The connect completed. This is the only positive evidence in the whole
    /// ingress stack that anything is listening.
    Open {
        /// How long the connect took, for an operator eyeballing a slow path.
        millis: u128,
    },
    /// The connect did not complete, in the transport's own words — refused,
    /// timed out, no route.
    Closed(String),
}

impl DialOutcome {
    /// One short label for a summary line.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Closed(_) => "CLOSED",
        }
    }

    /// Did anything answer?
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }
}

impl fmt::Display for DialOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { millis } => write!(f, "open ({millis}ms)"),
            Self::Closed(why) => write!(f, "CLOSED — {why}"),
        }
    }
}

/// One dialed address and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointCheck {
    /// The `host:port` dialed — exactly what the front door would dial.
    pub address: String,
    pub outcome: DialOutcome,
}

/// How one rule's placement resolved against a live discovery read.
///
/// Recorded *during* resolution rather than reconstructed after it, because two
/// of these three facts are unrecoverable from the resolved plan: whether the
/// address came from a pin or from the fleet, and which placement node supplied
/// it. Both are exactly what an operator needs to act on a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleResolution {
    pub hostname: String,
    pub slot: String,
    /// The rule already carried an address before the read — the slot pins
    /// `upstream_host`, and the pin wins everywhere (R844-F5/F12).
    ///
    /// Reported because it changes what the dial *means*: a pinned rule's
    /// connect measures whether a **declaration** answers, and the fleet has no
    /// say in what was dialed. That is the 127.0.0.1 case above.
    pub pinned: bool,
    /// Placement nodes that answered with a ready record on this rule's port.
    pub covered: Vec<String>,
    /// Placement nodes that did not, each with the reason — an `Unknown` node's
    /// own words, or "answered, and has no such record".
    pub missing: Vec<(String, String)>,
}

impl RuleResolution {
    /// Key under which a resolution is looked up once collation has grouped the
    /// rules by node.
    ///
    /// `(hostname, slot)` rather than hostname alone: one hostname is fronted
    /// through exactly one provider (`collate_front_doors` rejects otherwise),
    /// but the slot is what an operator opens to fix a finding, so carrying it
    /// costs nothing and a message without it points at no file.
    pub fn key(&self) -> (String, String) {
        (self.hostname.clone(), self.slot.clone())
    }
}

/// Everything the resolution pass learned, keyed for the verify pass.
pub type RuleResolutions = BTreeMap<(String, String), RuleResolution>;

/// Why one rule is not proven to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFinding {
    /// No port resolved — the slot declares `fronted = true`, pins no number,
    /// and no ready record supplied one.
    PortUnresolved,
    /// No address resolved. The detail carries whether the read was complete,
    /// because "the workload is not up" and "the node that has it could not be
    /// seen" are different facts (R844-F4).
    NoBackend { detail: String },
    /// Fewer backends than the rule's declared placement. Fatal on purpose —
    /// see the module doc.
    PartialPlacement {
        covered: Vec<String>,
        missing: Vec<(String, String)>,
    },
    /// A resolved address did not answer. The one finding no offline pass could
    /// ever produce.
    Unreachable {
        address: String,
        why: String,
        /// The address came from the slot's `upstream_host` rather than from a
        /// service record. Carried because it changes *which* claim just got
        /// falsified — a discovered address that refuses means the record and
        /// the world disagree, a pinned one means the TOML is wrong — and a
        /// message that names the wrong one sends the operator to the wrong
        /// file. Caught by running this verb against a mirror with a bogus pin.
        from_pin: bool,
    },
    /// No resolution was recorded for this rule at all — a bug in the caller's
    /// wiring rather than a fact about the fleet, reported instead of silently
    /// rendering the rule as fine.
    Unresolved,
    /// The public hostname did not answer at all — DNS, TLS, connect, timeout
    /// (R844-F18). The one finding that speaks for the public rather than for
    /// the mesh.
    PublicPathFailed { hostname: String, why: String },
    /// The public hostname answered with a status the public would read as
    /// broken. `503` here is the 2026-09-03 outage exactly: every mesh dial
    /// open, every record correct, and this the only signal that disagreed.
    PublicPathStatus { hostname: String, status: u16 },
    /// The public path and the backend the service record names are serving
    /// **different publishes** (R844-F18). The finding this ticket exists for:
    /// it is true precisely when the front door is dialing something other than
    /// the backend the rest of this report just proved reachable.
    PublicBackendDivergence {
        hostname: String,
        public_digest: String,
        address: String,
        backend_digest: String,
    },
}

impl VerifyFinding {
    /// Human-readable finding, in the imperative where there is something to do.
    pub fn message(&self) -> String {
        match self {
            Self::PortUnresolved => "no port resolved — the slot declares `fronted = true` \
                 without `port`, and no in-scope node reported a ready record naming one. \
                 Either the workload is not up, or its yubaba predates named ports and the \
                 record is ambiguous; pin `port = <n>` on the slot to publish it anyway."
                .to_string(),
            Self::NoBackend { detail } => {
                format!("no backend resolved — {detail}")
            }
            Self::PartialPlacement { covered, missing } => format!(
                "resolves {} of {} declared placement node(s) — a SUBSET that renders like a \
                 whole front door. Serving: {}. Missing: {}.",
                covered.len(),
                covered.len() + missing.len(),
                covered.join(", "),
                missing
                    .iter()
                    .map(|(m, why)| format!("{m} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::Unreachable {
                address,
                why,
                from_pin,
            } => {
                let origin = if *from_pin {
                    "The slot PINS this address in `upstream_host`, so nothing discovered it and \
                     nothing but this connect could have contradicted it — fix the pin, or drop \
                     it and let the fleet answer."
                } else {
                    "A ready service record is yubaba's OPINION; this connect is the measurement, \
                     and they disagree (R844-B11)."
                };
                format!("{address} did not answer — {why}. {origin}")
            }
            Self::Unresolved => "no discovery resolution was recorded for this rule — the \
                 verify pass planned it but never resolved it, which is a wiring bug in the \
                 caller, not a fact about the fleet."
                .to_string(),
            Self::PublicPathFailed { hostname, why } => format!(
                "https://{hostname}/ did not answer — {why}. Every line above measures the \
                 MESH side; this is the only one that measures what the public gets, so a \
                 report that is otherwise clean means the front door is not reaching the \
                 backend the records name."
            ),
            Self::PublicPathStatus { hostname, status } => format!(
                "https://{hostname}/ answered HTTP {status}. The backend above is reachable at \
                 the port its service record advertises, so the front door is configured to \
                 dial something else — that pair of facts is exactly the 2026-09-03 outage \
                 (R844-T10), where a redeploy moved the port and nothing reconfigured the door."
            ),
            Self::PublicBackendDivergence {
                hostname,
                public_digest,
                address,
                backend_digest,
            } => format!(
                "https://{hostname}/ and the backend its service record names are serving \
                 DIFFERENT publishes: the public path returns digest {public_digest}, {address} \
                 returns {backend_digest}. The hostname answers, so nothing else in this report \
                 can see it — the front door is dialing a backend other than the discovered one, \
                 or an edge cache is still holding the previous publish."
            ),
        }
    }
}

/// One rule's verdict on one front door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleVerdict {
    /// Node whose front door publishes this rule.
    pub machine: String,
    /// Front-door provider, as `IngressProvider::as_str`.
    pub provider: String,
    pub hostname: String,
    pub slot: String,
    pub port: Option<u16>,
    /// The address came from the slot's `upstream_host` pin, so the dial below
    /// measured a declaration rather than a discovered fact.
    pub pinned: bool,
    /// Every resolved backend, dialed.
    pub endpoints: Vec<EndpointCheck>,
    /// Empty means proven: every declared placement node resolved and every
    /// resolved address answered.
    pub findings: Vec<VerifyFinding>,
    /// Non-fatal context — today, the placement gaps of a *pinned* rule, where
    /// the pin overrides placement so a gap is worth saying and not worth
    /// failing.
    pub notes: Vec<String>,
}

impl RuleVerdict {
    /// Proven to serve.
    pub fn is_ok(&self) -> bool {
        self.findings.is_empty()
    }

    /// Every address this verdict dialed, in resolution order.
    pub fn addresses(&self) -> Vec<String> {
        self.endpoints
            .iter()
            .map(|e| e.address.clone())
            .collect()
    }

    /// This rule's port for a message, or `<unresolved>` — the same spelling
    /// [`IngressRule::port_label`] uses, so a verify line and a collate line
    /// describing one unresolved rule read identically.
    pub fn port_label(&self) -> String {
        self.port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "<unresolved>".to_string())
    }
}

/// Every rule on every collated front door, verified.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub verdicts: Vec<RuleVerdict>,
}

impl VerifyReport {
    /// Rules that are not proven to serve.
    pub fn failures(&self) -> impl Iterator<Item = &RuleVerdict> {
        self.verdicts.iter().filter(|v| !v.is_ok())
    }

    /// Nothing to fix.
    pub fn is_clean(&self) -> bool {
        self.failures().next().is_none()
    }
}

// ── The public path (R844-F18) ───────────────────────────────────────────────

/// What one HTTP GET of a publish beacon returned — the caller's measurement,
/// handed in as data like every other input on this seam.
///
/// The URL is always
/// `<base>/.well-known/yah-publish.json` ([`publish_beacon::BEACON_KEY`]),
/// because that object is the only thing on either side of the comparison that
/// *identifies which publish is being served*. A bare `GET /` cannot do this
/// job: a front door pointed at the wrong backend still answers 200 with a
/// plausible page, which is how `yah.dev` stayed frozen for nineteen days with
/// every signal green.
///
/// [`publish_beacon::BEACON_KEY`]: crate::reconciler::publish_beacon::BEACON_KEY
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconFetch {
    /// The request completed.
    Answered {
        status: u16,
        /// The `digest` field of the beacon, when the body parsed as one.
        /// `None` when it did not — a 404, or a hostname fronting something
        /// that is not a mesofact publish. That is a limit on the comparison,
        /// not a failure of the host, and is reported as a note.
        digest: Option<String>,
    },
    /// The request did not complete — DNS, TLS, connect, timeout.
    Failed(String),
}

/// Everything the caller measured on the public path, keyed for the pure pass.
///
/// Two maps rather than one because the two sides are addressed differently and
/// deduplicated differently: a hostname is fetched once however many front doors
/// publish it, and a backend address is fetched once however many hostnames
/// resolve to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicReadings {
    /// `hostname` → what `https://<hostname>/.well-known/yah-publish.json`
    /// returned. A hostname absent from this map was not measured, and
    /// [`apply_public_path`] says so rather than passing it.
    pub public: BTreeMap<String, BeaconFetch>,
    /// `host:port` → what `http://<host:port>/.well-known/yah-publish.json`
    /// returned, read over the mesh. This is "what the record claims", made
    /// comparable.
    pub backends: BTreeMap<String, BeaconFetch>,
}

/// Add the public-path verdict to a report that so far only knows the mesh
/// side (R844-F18).
///
/// ## The claim this closes
///
/// [`verify_collation`] answers *"is the backend reachable at the port its
/// record advertises"*. This answers *"and does the front door actually reach
/// it"* — the fourth row of the table in the module docs, which read `nothing
/// yet` until this landed. It closes it by comparing two publish beacons: the
/// one the **public** gets through the real front door, and the one the
/// **backend the record names** serves. They agree only if the door is dialing
/// that backend.
///
/// ## Detector, not oracle — read this before using it as a gate
///
/// It compares two *current* states. It cannot tell you what a config change is
/// about to do, because the front door has not been reconfigured yet: run it
/// before and after an apply and require both green. That is enough for the
/// failure it was built for — the divergence appears the moment the workload is
/// redeployed onto a new port — and it is not a general "is this edit safe"
/// oracle. Nothing in this module is.
///
/// ## The limit that cannot be designed away here
///
/// The public fetch goes wherever **DNS** sends it. A hostname published
/// through two front doors is measured at one of them, and this pass cannot say
/// which — so a divergence that affects only the other door reads as clean. The
/// verdicts for such a hostname carry a note saying so; closing it needs a fetch
/// pinned to each door's public address with a `Host` override, which needs a
/// public IP per door that nothing in the collation carries today.
pub fn apply_public_path(report: &mut VerifyReport, readings: &PublicReadings) {
    let doors_per_hostname = report.verdicts.iter().fold(
        BTreeMap::<String, usize>::new(),
        |mut acc, v| {
            *acc.entry(v.hostname.clone()).or_default() += 1;
            acc
        },
    );

    for verdict in &mut report.verdicts {
        let Some(fetched) = readings.public.get(&verdict.hostname) else {
            verdict.notes.push(format!(
                "the public path was not checked for {} — this verdict speaks only for the mesh \
                 side, which is necessary and not sufficient",
                verdict.hostname
            ));
            continue;
        };

        let public_digest = match fetched {
            BeaconFetch::Failed(why) => {
                verdict.findings.push(VerifyFinding::PublicPathFailed {
                    hostname: verdict.hostname.clone(),
                    why: why.clone(),
                });
                continue;
            }
            BeaconFetch::Answered { status, .. } if !(200..300).contains(status) => {
                verdict.findings.push(VerifyFinding::PublicPathStatus {
                    hostname: verdict.hostname.clone(),
                    status: *status,
                });
                continue;
            }
            BeaconFetch::Answered { digest, .. } => digest,
        };

        let Some(public_digest) = public_digest else {
            verdict.notes.push(format!(
                "https://{} answers, but serves no publish beacon, so the public path could not \
                 be COMPARED against the backend — only that something is there",
                verdict.hostname
            ));
            continue;
        };

        let mut compared = false;
        for endpoint in &verdict.endpoints {
            match readings.backends.get(&endpoint.address) {
                Some(BeaconFetch::Answered {
                    digest: Some(backend_digest),
                    ..
                }) => {
                    compared = true;
                    if backend_digest != public_digest {
                        verdict.findings.push(VerifyFinding::PublicBackendDivergence {
                            hostname: verdict.hostname.clone(),
                            public_digest: public_digest.clone(),
                            address: endpoint.address.clone(),
                            backend_digest: backend_digest.clone(),
                        });
                    }
                }
                // A backend that answers without a beacon, or does not answer
                // at all, leaves nothing to compare against. Not a finding of
                // its own: `verify_collation` already dialed it and said what
                // it found, and a second opinion phrased as an error would
                // double-count one fact.
                _ => {}
            }
        }

        if !compared {
            verdict.notes.push(format!(
                "https://{} answers with a publish beacon, but no discovered backend served one \
                 to compare it against, so this proves the hostname is up and NOT that it is \
                 fronting the discovered backend",
                verdict.hostname
            ));
        } else if doors_per_hostname
            .get(&verdict.hostname)
            .copied()
            .unwrap_or(0)
            > 1
        {
            // Only worth saying once a comparison actually happened: on a rule
            // where nothing could be compared, the note above is the finding
            // and this one is noise stacked on top of it.
            verdict.notes.push(format!(
                "{} is published through more than one front door and the public fetch went \
                 wherever DNS sent it, so this compares ONE of them",
                verdict.hostname
            ));
        }
    }
}

/// Fill one plan's rules from a live fanout **without stopping at the first
/// rule that cannot be dialed**, recording how each one resolved.
///
/// Deliberately not [`IngressPlan::resolve_upstreams_from`], though it applies
/// the same precedence (a rule that already has an address keeps it — the pin
/// always wins) and reads the same `upstreams_for`. That method `bail!`s on the
/// first undialable rule, which is right for an *apply*: publishing a front door
/// that is 80% correct is worse than publishing none. It is wrong for a
/// *verifier*, whose entire job is the complete picture — an operator who fixes
/// one rule and re-runs only to be told about the next one has been handed a
/// linked list instead of a report.
///
/// Ports must already be resolved ([`IngressPlan::resolve_ports_from`]):
/// discovery matches records by port, so a portless rule resolves no address
/// either and is reported as both.
pub fn resolve_upstreams_reporting(
    plan: &mut IngressPlan,
    fanout: &ServiceRecordFanout,
) -> Vec<RuleResolution> {
    let mut out = Vec::new();
    for rule in &mut plan.rules {
        let pinned = !rule.upstream_hosts.is_empty();
        if !pinned {
            rule.upstream_hosts = fanout.upstreams_for(rule);
        }
        let (covered, missing) = placement_coverage(rule, fanout);
        out.push(RuleResolution {
            hostname: rule.hostname.clone(),
            slot: rule.slot.clone(),
            pinned,
            covered,
            missing,
        });
    }
    out
}

/// Which of a rule's declared placement nodes actually supplied a backend, and
/// why each of the others did not.
///
/// Mirrors [`ServiceRecordFanout::upstreams_for`]'s matching (by port, scoped to
/// the rule's placement) so the two cannot disagree about what "covered" means —
/// it answers *which nodes* produced that method's addresses, one level of
/// detail below what it returns.
fn placement_coverage(
    rule: &IngressRule,
    fanout: &ServiceRecordFanout,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut covered = Vec::new();
    let mut missing = Vec::new();
    for machine in &rule.machines {
        match fanout.nodes.get(machine.as_str()) {
            None => missing.push((
                machine.clone(),
                "was never asked — it is not in the set this read fanned out over".to_string(),
            )),
            Some(visibility) => match visibility.unknown_reason() {
                Some(reason) => missing.push((machine.clone(), reason.to_string())),
                None => {
                    let serving = rule.port.is_some_and(|port| {
                        visibility
                            .records()
                            .iter()
                            .any(|r| r.ports.contains(&port))
                    });
                    if serving {
                        covered.push(machine.clone());
                    } else {
                        missing.push((
                            machine.clone(),
                            match rule.port {
                                Some(port) => format!(
                                    "answered, and reports no ready record on port {port}"
                                ),
                                None => "the rule has no resolved port to match a record on"
                                    .to_string(),
                            },
                        ));
                    }
                }
            },
        }
    }
    (covered, missing)
}

/// Verify every rule on every collated front door: check the resolution, then
/// dial what it produced.
///
/// `dial` is the caller's TCP connect. Each distinct address is dialed **once**
/// — a rule published through two front doors is the same backend twice, and
/// two connects would be two chances to disagree about one fact.
///
/// `read_note` is [`ServiceRecordFanout::unknown_note`]: when the fanout could
/// not see part of the fleet, an empty resolution is `UNKNOWN`, not `absent`,
/// and every [`VerifyFinding::NoBackend`] says so rather than asserting the
/// workload is down.
///
/// Verdicts come back in front-door order, then rule order — the same walk the
/// collation itself renders in, so a caller may stream the two side by side
/// rather than looking each verdict up.
pub fn verify_collation<D>(
    collation: &Collation,
    resolutions: &RuleResolutions,
    read_note: Option<&str>,
    mut dial: D,
) -> VerifyReport
where
    D: FnMut(&str) -> DialOutcome,
{
    let mut dialed: BTreeMap<String, DialOutcome> = BTreeMap::new();
    let mut verdicts = Vec::new();

    for door in &collation.front_doors {
        for rule in &door.rules {
            let mut findings = Vec::new();
            let mut notes = Vec::new();
            let key = (rule.hostname.clone(), rule.slot.clone());
            let resolution = resolutions.get(&key);

            let pinned = resolution.is_some_and(|r| r.pinned);
            if resolution.is_none() {
                findings.push(VerifyFinding::Unresolved);
            }

            if rule.port.is_none() {
                findings.push(VerifyFinding::PortUnresolved);
            }

            if rule.upstream_hosts.is_empty() {
                findings.push(VerifyFinding::NoBackend {
                    detail: match read_note {
                        Some(note) => format!(
                            "and the discovery read was PARTIAL, so this is UNKNOWN rather than \
                             empty: {note}"
                        ),
                        None => "every node in scope answered and none reports a ready record \
                                 for it, so the workload is not serving"
                            .to_string(),
                    },
                });
            } else if let Some(res) = resolution {
                if !res.missing.is_empty() {
                    if pinned {
                        // The pin overrides placement, so a gap is not a
                        // shortfall in what gets published — but it IS the
                        // shape that hid the 127.0.0.1 drift, so it is said
                        // out loud rather than dropped.
                        notes.push(format!(
                            "slot pins `upstream_host`, so this dialed a DECLARATION, not a \
                             discovered address; {} placement node(s) report no ready record \
                             for it: {}",
                            res.missing.len(),
                            res.missing
                                .iter()
                                .map(|(m, why)| format!("{m} ({why})"))
                                .collect::<Vec<_>>()
                                .join("; ")
                        ));
                    } else {
                        findings.push(VerifyFinding::PartialPlacement {
                            covered: res.covered.clone(),
                            missing: res.missing.clone(),
                        });
                    }
                }
            }

            let mut endpoints = Vec::new();
            if let Ok(addrs) = rule.upstreams() {
                for address in addrs {
                    let outcome = match dialed.get(&address) {
                        Some(prior) => prior.clone(),
                        None => {
                            let outcome = dial(&address);
                            dialed.insert(address.clone(), outcome.clone());
                            outcome
                        }
                    };
                    if let DialOutcome::Closed(why) = &outcome {
                        findings.push(VerifyFinding::Unreachable {
                            address: address.clone(),
                            why: why.clone(),
                            from_pin: pinned,
                        });
                    }
                    endpoints.push(EndpointCheck { address, outcome });
                }
            }

            verdicts.push(RuleVerdict {
                machine: door.machine.clone(),
                provider: door.provider.as_str().to_string(),
                hostname: rule.hostname.clone(),
                slot: rule.slot.clone(),
                port: rule.port,
                pinned,
                endpoints,
                findings,
                notes,
            });
        }
    }

    VerifyReport { verdicts }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IngressProvider;
    use crate::reconciler::ingress::{collate_front_doors, PlannedEdge};
    use crate::reconciler::service_discovery::{DiscoveredRecord, UnknownReason};

    fn rule(hostname: &str, port: Option<u16>, machines: &[&str]) -> IngressRule {
        IngressRule {
            hostname: hostname.to_string(),
            port,
            slot: "bundle".to_string(),
            provider_id: None,
            machines: machines.iter().map(|m| m.to_string()).collect(),
            upstream_hosts: vec![],
        }
    }

    fn plan(rules: Vec<IngressRule>, front_doors: &[&str]) -> IngressPlan {
        IngressPlan {
            provider: IngressProvider::Passway,
            rules,
            front_doors: front_doors.iter().map(|m| m.to_string()).collect(),
            tunnel_id: None,
            edge_provider_id: None,
            image: None,
        }
    }

    fn record(ident: &str, mesh_ip: &str, ports: &[u16]) -> DiscoveredRecord {
        DiscoveredRecord {
            ident: ident.to_string(),
            mesh_ip: mesh_ip.to_string(),
            ports: ports.to_vec(),
            named_ports: Default::default(),
        }
    }

    /// Plan → resolve → collate → verify, the whole pipeline the CLI runs.
    fn run(
        mut plans: Vec<(&str, &str, IngressPlan)>,
        fanout: &ServiceRecordFanout,
        dial: impl FnMut(&str) -> DialOutcome,
    ) -> VerifyReport {
        let mut resolutions = RuleResolutions::new();
        let mut planned = Vec::new();
        for (service, env, plan) in &mut plans {
            for res in resolve_upstreams_reporting(plan, fanout) {
                resolutions.insert(res.key(), res);
            }
            planned.push(PlannedEdge {
                service: service.to_string(),
                env: env.to_string(),
                plan: plan.clone(),
            });
        }
        let collation = collate_front_doors(&planned).unwrap();
        let note = fanout.unknown_note();
        verify_collation(&collation, &resolutions, note.as_deref(), dial)
    }

    fn always_open(_: &str) -> DialOutcome {
        DialOutcome::Open { millis: 1 }
    }

    #[test]
    fn a_resolved_rule_whose_endpoint_answers_is_clean() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(8080), &["us-east-001"])],
                    &["us-east-001"],
                ),
            )],
            &fanout,
            always_open,
        );

        assert!(report.is_clean(), "{:#?}", report.verdicts);
        assert_eq!(report.verdicts.len(), 1);
        assert_eq!(report.verdicts[0].addresses(), vec!["100.64.0.3:8080"]);
        assert!(!report.verdicts[0].pinned);
    }

    #[test]
    fn a_ready_record_whose_address_refuses_is_a_failure() {
        // R844-B11 in miniature: the record is Ready and every offline check
        // passes; only the connect knows.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-west-001",
            vec![record("yah-marketing", "100.64.0.3", &[4325])],
        );

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(4325), &["us-west-001"])],
                    &["us-west-001"],
                ),
            )],
            &fanout,
            |_| DialOutcome::Closed("connection refused".to_string()),
        );

        assert!(!report.is_clean());
        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("100.64.0.3:4325"), "{msg}");
        assert!(msg.contains("connection refused"), "{msg}");
        assert!(
            msg.contains("OPINION"),
            "a DISCOVERED address that refuses means the record and the world \
             disagree, and the message has to say which: {msg}"
        );
    }

    #[test]
    fn an_unreachable_pin_blames_the_toml_not_a_service_record() {
        // Found by running the verb against a mirror pinning a dead address:
        // the message told the operator a service record disagreed with the
        // world, when nothing had discovered anything — the address came
        // straight off the slot, and that is the file to open.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );

        let mut pinned_rule = rule("yah.dev", Some(8080), &["us-east-001"]);
        pinned_rule.upstream_hosts = vec!["100.64.0.99".to_string()];

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(vec![pinned_rule], &["us-east-001"]),
            )],
            &fanout,
            |_| DialOutcome::Closed("connection timed out".to_string()),
        );

        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("upstream_host"), "{msg}");
        assert!(
            !msg.contains("OPINION"),
            "no record was consulted, so none can be blamed: {msg}"
        );
    }

    #[test]
    fn resolving_a_subset_of_the_declared_placement_fails() {
        // The failure class this verb exists to remove: one of two nodes
        // answers, the rule renders and dials fine, and half the front door is
        // silently absent.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );
        fanout.push_answer("us-west-001", vec![]);

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(8080), &["us-east-001", "us-west-001"])],
                    &["us-east-001"],
                ),
            )],
            &fanout,
            always_open,
        );

        assert!(!report.is_clean(), "a subset must not pass");
        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("1 of 2"), "{msg}");
        assert!(msg.contains("us-west-001"), "{msg}");
        // The address it DID resolve is still reported — a failure that hides
        // the working half is a worse report, not a stricter one.
        assert_eq!(report.verdicts[0].addresses(), vec!["100.64.0.3:8080"]);
    }

    #[test]
    fn an_unseen_placement_node_fails_as_unknown_not_as_down() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );
        fanout.push_unknown(
            "us-west-001",
            UnknownReason::Unreachable("no route to host".to_string()),
        );

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(8080), &["us-east-001", "us-west-001"])],
                    &["us-east-001"],
                ),
            )],
            &fanout,
            always_open,
        );

        assert!(!report.is_clean());
        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("us-west-001"), "{msg}");
        assert!(msg.contains("no route to host"), "{msg}");
    }

    #[test]
    fn a_rule_with_no_record_anywhere_reports_no_backend_on_a_complete_read() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![]);

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(8080), &["us-east-001"])],
                    &["us-east-001"],
                ),
            )],
            &fanout,
            always_open,
        );

        assert!(!report.is_clean());
        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("not serving"), "{msg}");
        assert!(
            !msg.contains("PARTIAL"),
            "a complete read must not hedge: {msg}"
        );
    }

    #[test]
    fn a_rule_with_no_record_on_a_partial_read_says_unknown_rather_than_down() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_unknown(
            "us-east-001",
            UnknownReason::EndpointAbsent("GET … returned 404".to_string()),
        );

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(8080), &["us-east-001"])],
                    &["us-east-001"],
                ),
            )],
            &fanout,
            always_open,
        );

        assert!(!report.is_clean());
        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("UNKNOWN"), "{msg}");
        assert!(msg.contains("404"), "{msg}");
    }

    #[test]
    fn a_portless_rule_reports_both_halves_rather_than_only_the_address() {
        // The `fronted = true` shape with nothing to match on: it must not read
        // as "the address is missing" alone.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![]);

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(vec![rule("yah.dev", None, &["us-east-001"])], &["us-east-001"]),
            )],
            &fanout,
            always_open,
        );

        let findings = &report.verdicts[0].findings;
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, VerifyFinding::PortUnresolved)),
            "{findings:#?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, VerifyFinding::NoBackend { .. })),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_pinned_upstream_is_dialed_and_flagged_as_a_declaration() {
        // The 127.0.0.1 case. The pin wins, so the dial is still performed —
        // but the verdict has to say the address came from a TOML, and the
        // placement gap it papers over has to be visible.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer("us-east-001", vec![]);

        let mut pinned_rule = rule("yah.dev", Some(8080), &["us-east-001"]);
        pinned_rule.upstream_hosts = vec!["127.0.0.1".to_string()];

        let mut dialed: Vec<String> = Vec::new();
        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(vec![pinned_rule], &["us-east-001"]),
            )],
            &fanout,
            |addr| {
                dialed.push(addr.to_string());
                DialOutcome::Open { millis: 1 }
            },
        );

        assert_eq!(dialed, vec!["127.0.0.1:8080"]);
        let v = &report.verdicts[0];
        assert!(v.pinned);
        assert!(v.is_ok(), "a pin that answers is not a failure: {v:#?}");
        assert_eq!(v.notes.len(), 1, "{:#?}", v.notes);
        assert!(v.notes[0].contains("DECLARATION"), "{}", v.notes[0]);
        assert!(v.notes[0].contains("us-east-001"), "{}", v.notes[0]);
    }

    #[test]
    fn one_backend_published_through_two_front_doors_is_dialed_once() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );

        let mut dialed: Vec<String> = Vec::new();
        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(8080), &["us-east-001"])],
                    &["us-east-001", "us-west-001"],
                ),
            )],
            &fanout,
            |addr| {
                dialed.push(addr.to_string());
                DialOutcome::Open { millis: 1 }
            },
        );

        assert_eq!(
            report.verdicts.len(),
            2,
            "both front doors publish the rule, so both are verified"
        );
        assert_eq!(dialed, vec!["100.64.0.3:8080"], "dialed twice");
        assert!(report.is_clean());
    }

    #[test]
    fn every_rule_is_reported_even_after_one_of_them_fails() {
        // The reason this does not call `resolve_upstreams_from`: an operator
        // fixing one rule at a time is being handed a linked list.
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );

        let report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![
                        rule("a.yah.dev", Some(9999), &["us-east-001"]),
                        rule("b.yah.dev", Some(8080), &["us-east-001"]),
                    ],
                    &["us-east-001"],
                ),
            )],
            &fanout,
            always_open,
        );

        assert_eq!(report.verdicts.len(), 2);
        let a = report
            .verdicts
            .iter()
            .find(|v| v.hostname == "a.yah.dev")
            .unwrap();
        let b = report
            .verdicts
            .iter()
            .find(|v| v.hostname == "b.yah.dev")
            .unwrap();
        assert!(!a.is_ok(), "the unresolvable rule fails");
        assert!(
            b.is_ok(),
            "and the rule after it is still resolved and dialed: {b:#?}"
        );
    }

    // ── the public path (R844-F18) ───────────────────────────────────────────

    /// The healthy apex: one hostname, one door, one backend, both sides
    /// serving the same publish.
    fn healthy_report() -> VerifyReport {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );
        run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule("yah.dev", Some(8080), &["us-east-001"])],
                    &["us-east-001"],
                ),
            )],
            &fanout,
            always_open,
        )
    }

    fn served(digest: &str) -> BeaconFetch {
        BeaconFetch::Answered {
            status: 200,
            digest: Some(digest.to_string()),
        }
    }

    #[test]
    fn matching_beacons_on_both_sides_leave_the_verdict_clean() {
        let mut report = healthy_report();
        let readings = PublicReadings {
            public: [("yah.dev".to_string(), served("abc123"))]
                .into_iter()
                .collect(),
            backends: [("100.64.0.3:8080".to_string(), served("abc123"))]
                .into_iter()
                .collect(),
        };
        apply_public_path(&mut report, &readings);
        assert!(report.is_clean(), "{:#?}", report.verdicts);
        assert!(
            report.verdicts[0].notes.is_empty(),
            "a fully compared rule has nothing to caveat: {:?}",
            report.verdicts[0].notes
        );
    }

    /// THE 2026-09-03 OUTAGE, reproduced as a unit test. Every mesh signal is
    /// green — the record is correct, the address answers, `verify_collation`
    /// alone reports the rule clean — and the public gets a 503 because the
    /// running front door is still dialing the port the workload left.
    #[test]
    fn a_503_at_the_apex_fails_a_rule_whose_mesh_side_is_entirely_green() {
        let mut report = healthy_report();
        assert!(
            report.is_clean(),
            "precondition: the mesh side is what reported success during the outage"
        );

        let readings = PublicReadings {
            public: [(
                "yah.dev".to_string(),
                BeaconFetch::Answered {
                    status: 503,
                    digest: None,
                },
            )]
            .into_iter()
            .collect(),
            backends: [("100.64.0.3:8080".to_string(), served("abc123"))]
                .into_iter()
                .collect(),
        };
        apply_public_path(&mut report, &readings);

        assert!(!report.is_clean());
        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("503"), "{msg}");
        assert!(
            msg.contains("yah.dev"),
            "the finding names the hostname the public dials: {msg}"
        );
    }

    /// The stale-serve shape: the hostname answers 200 with a real page, so
    /// nothing short of comparing publishes can see it. This is the failure
    /// that froze the apex for nineteen days.
    #[test]
    fn a_200_serving_a_different_publish_than_the_backend_is_a_failure() {
        let mut report = healthy_report();
        let readings = PublicReadings {
            public: [("yah.dev".to_string(), served("old-digest"))]
                .into_iter()
                .collect(),
            backends: [("100.64.0.3:8080".to_string(), served("new-digest"))]
                .into_iter()
                .collect(),
        };
        apply_public_path(&mut report, &readings);

        assert!(!report.is_clean());
        let msg = report.verdicts[0].findings[0].message();
        assert!(msg.contains("old-digest"), "{msg}");
        assert!(msg.contains("new-digest"), "{msg}");
        assert!(
            msg.contains("100.64.0.3:8080"),
            "and it names the backend it compared against: {msg}"
        );
    }

    #[test]
    fn a_public_path_that_does_not_answer_at_all_is_a_failure() {
        let mut report = healthy_report();
        let readings = PublicReadings {
            public: [(
                "yah.dev".to_string(),
                BeaconFetch::Failed("dns error: no record".to_string()),
            )]
            .into_iter()
            .collect(),
            backends: [("100.64.0.3:8080".to_string(), served("abc123"))]
                .into_iter()
                .collect(),
        };
        apply_public_path(&mut report, &readings);

        assert!(!report.is_clean());
        assert!(report.verdicts[0].findings[0]
            .message()
            .contains("dns error"));
    }

    /// A hostname fronting something that is not a mesofact publish has no
    /// beacon to compare. That is a limit on the CHECK, not a fault of the
    /// host — so it is a note, and the rule stays clean rather than failing
    /// every non-bundle hostname in the fleet.
    #[test]
    fn a_hostname_with_no_beacon_is_noted_and_not_failed() {
        let mut report = healthy_report();
        let readings = PublicReadings {
            public: [(
                "yah.dev".to_string(),
                BeaconFetch::Answered {
                    status: 200,
                    digest: None,
                },
            )]
            .into_iter()
            .collect(),
            backends: [("100.64.0.3:8080".to_string(), served("abc123"))]
                .into_iter()
                .collect(),
        };
        apply_public_path(&mut report, &readings);

        assert!(report.is_clean(), "{:#?}", report.verdicts);
        assert!(
            report.verdicts[0]
                .notes
                .iter()
                .any(|n| n.contains("no publish beacon")),
            "{:?}",
            report.verdicts[0].notes
        );
    }

    /// The distinction this whole relay is about: "answers" is not "answers
    /// with the backend we just proved". A public 200 with no comparable
    /// backend must not read as a full pass.
    #[test]
    fn a_public_200_with_nothing_to_compare_says_so_rather_than_implying_a_match() {
        let mut report = healthy_report();
        let readings = PublicReadings {
            public: [("yah.dev".to_string(), served("abc123"))]
                .into_iter()
                .collect(),
            backends: BTreeMap::new(),
        };
        apply_public_path(&mut report, &readings);

        assert!(report.is_clean());
        assert!(
            report.verdicts[0]
                .notes
                .iter()
                .any(|n| n.contains("NOT that it is fronting the discovered backend")),
            "{:?}",
            report.verdicts[0].notes
        );
    }

    #[test]
    fn an_unmeasured_hostname_is_marked_as_unmeasured_not_as_passing() {
        let mut report = healthy_report();
        apply_public_path(&mut report, &PublicReadings::default());

        assert!(report.is_clean(), "not checking is not failing");
        assert!(
            report.verdicts[0]
                .notes
                .iter()
                .any(|n| n.contains("was not checked")),
            "{:?}",
            report.verdicts[0].notes
        );
    }

    /// DNS picks one door, so the comparison covers one door. Saying that is
    /// the difference between a caveat and a false claim of coverage.
    #[test]
    fn a_hostname_on_two_front_doors_is_noted_as_measured_at_only_one() {
        let mut fanout = ServiceRecordFanout::default();
        fanout.push_answer(
            "us-east-001",
            vec![record("yah-marketing", "100.64.0.3", &[8080])],
        );
        fanout.push_answer(
            "us-south-001",
            vec![record("yah-marketing", "100.64.0.2", &[8080])],
        );
        let mut report = run(
            vec![(
                "yah-marketing",
                "cloud",
                plan(
                    vec![rule(
                        "yah.dev",
                        Some(8080),
                        &["us-east-001", "us-south-001"],
                    )],
                    &["us-east-001", "us-south-001"],
                ),
            )],
            &fanout,
            always_open,
        );
        assert_eq!(report.verdicts.len(), 2, "one verdict per front door");

        let readings = PublicReadings {
            public: [("yah.dev".to_string(), served("abc123"))]
                .into_iter()
                .collect(),
            backends: [
                ("100.64.0.3:8080".to_string(), served("abc123")),
                ("100.64.0.2:8080".to_string(), served("abc123")),
            ]
            .into_iter()
            .collect(),
        };
        apply_public_path(&mut report, &readings);

        assert!(report.is_clean(), "{:#?}", report.verdicts);
        assert!(
            report
                .verdicts
                .iter()
                .all(|v| v.notes.iter().any(|n| n.contains("wherever DNS sent it"))),
            "{:#?}",
            report.verdicts
        );
    }
}
